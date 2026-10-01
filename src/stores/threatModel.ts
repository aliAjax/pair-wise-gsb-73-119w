import { computed, ref } from 'vue'
import { defineStore } from 'pinia'
import type {
  ActorRole,
  AuditEvent,
  CleanupJob,
  DecisionType,
  Threat,
  ThreatModelState,
  VersionSnapshot,
} from '@/models/domain'
import {
  commitState,
  ConcurrentUpdateError,
  createId,
  loadState,
  resetState,
} from '@/services/repository'
import {
  applyRemovalPlan,
  buildRemovalPlan,
  type CleanupTargetKind,
  type RemovalPlan,
} from '@/services/lifecycle'
import {
  activeThreats,
  dashboardMetrics,
  decisionsForThreat,
  getValidationIssues,
  reviewProgress,
} from '@/services/selectors'

type CollectionKey =
  | 'zones'
  | 'components'
  | 'dependencies'
  | 'flows'
  | 'controls'
  | 'evidence'
  | 'threats'
  | 'attackPaths'
  | 'risks'
  | 'mitigations'
  | 'decisions'

interface IdentifiedEntity {
  id: string
}

const STORAGE_KEY = 'scapex-threat-model-v1'

export class PlanConflictError extends Error {
  constructor() {
    super('引用关系在打开核对窗口后已发生变化，请重新核对后再提交')
    this.name = 'PlanConflictError'
  }
}

export const useThreatModelStore = defineStore('threat-model', () => {
  const data = ref<ThreatModelState>(loadState())
  const lastSavedAt = ref(new Date().toISOString())
  /** 最近一次跨窗口冲突，供界面提示后重新核对 */
  const lastConflict = ref('')

  const metrics = computed(() => dashboardMetrics(data.value))
  const issues = computed(() => getValidationIssues(data.value))
  const pendingReviews = computed(() =>
    activeThreats(data.value).filter((threat) => threat.reviewStatus === 'in_review'),
  )
  const interruptedJobs = computed(() =>
    data.value.cleanupJobs.filter((job) => job.status === 'interrupted'),
  )

  /**
   * 所有写操作的统一出口：基于 dataVersion 的乐观锁提交。
   * 另一窗口已提交时这里抛出 ConcurrentUpdateError，本地状态随后由
   * storage 监听刷新为最新引用视图，调用方需重新核对再提交。
   */
  const withCommit = <T>(mutate: (draft: ThreatModelState) => T, expected?: string): T => {
    const expectedVersion = expected ?? data.value.dataVersion
    const draft = structuredClone(data.value) as ThreatModelState
    const result = mutate(draft)
    try {
      commitState(draft, expectedVersion)
    } catch (error) {
      if (error instanceof ConcurrentUpdateError) {
        lastConflict.value = error.message
        // 立即载入另一窗口提交后的最新引用视图
        data.value = loadState()
      }
      throw error
    }
    data.value = loadState()
    lastSavedAt.value = new Date().toISOString()
    return result
  }

  // 跨窗口同步：另一标签页提交后，本窗口自动刷新到最新引用结果
  if (typeof window !== 'undefined') {
    window.addEventListener('storage', (event) => {
      if (event.key !== STORAGE_KEY || !event.newValue) return
      try {
        const next = JSON.parse(event.newValue) as ThreatModelState
        if (next.dataVersion && next.dataVersion !== data.value.dataVersion) {
          data.value = next
          lastSavedAt.value = new Date().toISOString()
        }
      } catch {
        // 忽略无法解析的存储内容
      }
    })
  }

  const appendAudit = (
    draft: ThreatModelState,
    entityType: string,
    entityId: string,
    action: string,
    detail: string,
  ): void => {
    const event: AuditEvent = {
      id: createId('aud'),
      entityType,
      entityId,
      action,
      actor: '当前用户',
      createdAt: new Date().toISOString(),
      detail,
    }
    draft.audit.unshift(event)
  }

  const saveEntity = (collection: CollectionKey, item: IdentifiedEntity): void => {
    withCommit((draft) => {
      const target = draft[collection] as unknown as IdentifiedEntity[]
      const index = target.findIndex((entry) => entry.id === item.id)
      if (index >= 0) {
        target[index] = structuredClone(item)
      } else {
        target.unshift(structuredClone(item))
      }
      const label = 'name' in item && typeof item.name === 'string' ? item.name : item.id
      appendAudit(draft, collection, item.id, index >= 0 ? '更新' : '新增', `${label} 已保存`)
    })
  }

  const updateBoundary = (boundary: ThreatModelState['boundary']): void => {
    withCommit((draft) => {
      draft.boundary = boundary
      appendAudit(draft, 'boundary', boundary.id, '更新', `${boundary.name} 的系统边界已更新`)
    })
  }

  const saveThreat = (threat: Threat): void => {
    saveEntity('threats', threat)
  }

  const planCleanup = (
    targets: { kind: CleanupTargetKind; id: string }[],
  ): RemovalPlan => buildRemovalPlan(data.value, targets)

  /**
   * 提交清理：再次按当前状态重建计划，与打开核对窗口时的签名比对，
   * 若另一窗口已经移除/重建同一编号（引用集合变化），拒绝提交。
   */
  const submitCleanup = (plan: RemovalPlan): void => {
    const targets = plan.targets.map((target) => ({ kind: target.kind, id: target.id }))
    const current = buildRemovalPlan(data.value, targets)
    if (current.signature !== plan.signature || current.fingerprint !== plan.fingerprint) {
      throw new PlanConflictError()
    }
    withCommit((draft) => {
      const outcome = applyRemovalPlan(draft, current)
      // 回到待重审：清掉当前修订轮次的会签意见，历史轮次意见按 revision 保留
      outcome.resetThreatIds.forEach((threatId) => {
        const threat = draft.threats.find((item) => item.id === threatId)
        if (!threat) return
        draft.decisions = draft.decisions.filter(
          (decision) => !(decision.threatId === threatId && decision.revision === threat.revision),
        )
      })
      appendAudit(
        draft,
        'cleanup',
        current.signature,
        '架构清理',
        `停用 ${outcome.deactivated.length} 项，彻底移除 ${outcome.deleted.length} 项，` +
          `${outcome.resetThreatIds.length} 条威胁回到待重审，` +
          `${outcome.prunedDraftThreatIds.length} 条草稿威胁引用已剪除。`,
      )
    })
  }

  /** 批量清理：逐目标落库，中断时保留未完成项，下次可续跑 */
  const startBatchCleanup = (
    kind: CleanupTargetKind,
    targetIds: string[],
  ): CleanupJob => {
    const job: CleanupJob = {
      id: createId('job'),
      createdAt: new Date().toISOString(),
      kind,
      targetIds: [...targetIds],
      completedSignatures: [],
      status: 'running',
      failedSignatures: [],
      updatedAt: new Date().toISOString(),
    }
    withCommit((draft) => {
      draft.cleanupJobs.unshift(job)
      appendAudit(draft, 'cleanup_job', job.id, '发起批量清理', `${targetIds.length} 个编号进入批量处理队列。`)
    })
    runCleanupJob(job.id)
    return job
  }

  const runCleanupJob = (jobId: string): void => {
    // eslint-disable-next-line no-constant-condition
    while (true) {
      const job = data.value.cleanupJobs.find((item) => item.id === jobId)
      if (!job || job.status === 'done') return

      const remaining = job.targetIds.filter(
        (id) => !job.completedSignatures.includes(`${job.kind}:${id}`),
      )
      if (remaining.length === 0) {
        withCommit((draft) => {
          const current = draft.cleanupJobs.find((item) => item.id === jobId)
          if (current) {
            current.status = 'done'
            current.updatedAt = new Date().toISOString()
          }
          appendAudit(draft, 'cleanup_job', jobId, '批量清理完成', '全部编号处理完毕。')
        })
        return
      }

      const nextId = remaining[0]
      const signature = `${job.kind}:${nextId}`
      try {
        submitCleanup(buildRemovalPlan(data.value, [{ kind: job.kind, id: nextId }]))
        withCommit((draft) => {
          const current = draft.cleanupJobs.find((item) => item.id === jobId)
          if (current && !current.completedSignatures.includes(signature)) {
            current.completedSignatures.push(signature)
            current.failedSignatures = current.failedSignatures.filter((item) => item !== signature)
            current.status = 'running'
            current.lastError = undefined
            current.updatedAt = new Date().toISOString()
          }
        })
      } catch (error) {
        const detail = error instanceof Error ? error.message : '未知错误'
        try {
          withCommit((draft) => {
            const current = draft.cleanupJobs.find((item) => item.id === jobId)
            if (current) {
              current.status = 'interrupted'
              current.lastError = detail
              if (!current.failedSignatures.includes(signature)) current.failedSignatures.push(signature)
              current.updatedAt = new Date().toISOString()
            }
          })
        } catch {
          // 记账失败时保持中断状态，等待恢复
        }
        return
      }
    }
  }

  const resumeCleanupJob = (jobId: string): void => {
    runCleanupJob(jobId)
  }

  const dismissCleanupJob = (jobId: string): void => {
    withCommit((draft) => {
      draft.cleanupJobs = draft.cleanupJobs.filter((job) => job.id !== jobId)
      appendAudit(draft, 'cleanup_job', jobId, '清理任务关闭', '中断任务已人工关闭。')
    })
  }

  const createVersion = (
    label: string,
    notes: string,
    affectedThreatIds: string[],
  ): VersionSnapshot => {
    return withCommit((draft) => {
      const revision = draft.currentRevision + 1
      const snapshot: VersionSnapshot = {
        id: createId('ver'),
        revision,
        label,
        createdAt: new Date().toISOString(),
        author: '当前用户',
        notes,
        threatIds: draft.threats.filter((threat) => threat.lifecycle?.status !== 'inactive').map((threat) => threat.id),
        componentIds: draft.components.filter((item) => item.lifecycle?.status !== 'inactive').map((item) => item.id),
        flowIds: draft.flows.filter((item) => item.lifecycle?.status !== 'inactive').map((item) => item.id),
        controlIds: draft.controls.filter((item) => item.lifecycle?.status !== 'inactive').map((item) => item.id),
        riskIds: draft.risks.filter((item) => item.lifecycle?.status !== 'inactive').map((item) => item.id),
        affectedThreatIds,
      }
      draft.currentRevision = revision
      draft.versions.unshift(snapshot)
      draft.threats = draft.threats.map((threat) => {
        if (!affectedThreatIds.includes(threat.id)) {
          return { ...threat, revision }
        }
        return { ...threat, revision, reviewStatus: 'in_review' as const }
      })
      appendAudit(
        draft,
        'version',
        snapshot.id,
        '创建版本',
        `${label} 已创建，${affectedThreatIds.length} 条威胁进入重新审核`,
      )
      return snapshot
    })
  }

  const submitDecision = (
    threatId: string,
    role: ActorRole,
    decision: DecisionType,
    actor: string,
    comment: string,
  ): void => {
    withCommit((draft) => {
      const threat = draft.threats.find((item) => item.id === threatId)
      if (!threat) return
      draft.decisions = draft.decisions.filter(
        (item) => !(item.threatId === threatId && item.role === role && item.revision === threat.revision),
      )
      draft.decisions.unshift({
        id: createId('dec'),
        threatId,
        role,
        decision,
        actor,
        comment,
        createdAt: new Date().toISOString(),
        revision: threat.revision,
      })

      const currentDecisions = decisionsForThreat(draft.decisions, threatId, threat.revision)
      const requiredRoles: ActorRole[] = ['development', 'security', 'business']
      const allSubmitted = requiredRoles.every((requiredRole) =>
        currentDecisions.some((item) => item.role === requiredRole),
      )
      if (currentDecisions.some((item) => item.decision === 'rejected')) {
        threat.reviewStatus = 'rejected'
      } else if (
        allSubmitted &&
        currentDecisions.every((item) => item.decision === 'approved')
      ) {
        threat.reviewStatus = 'approved'
      } else {
        threat.reviewStatus = 'in_review'
      }

      const decisionLabel: Record<DecisionType, string> = {
        accept: '接受',
        degrade: '降级',
        evidence_required: '要求补证',
        approved: '会签通过',
        rejected: '驳回',
      }
      appendAudit(
        draft,
        'threat',
        threatId,
        decisionLabel[decision],
        `${actor}（${role}）提交会签意见`,
      )
    })
  }

  const updateMitigationStatus = (
    taskId: string,
    status: ThreatModelState['mitigations'][number]['status'],
  ): void => {
    withCommit((draft) => {
      const task = draft.mitigations.find((item) => item.id === taskId)
      if (!task) return
      task.status = status
      appendAudit(draft, 'mitigation', task.id, '更新状态', `${task.title} 更新为 ${status}`)
    })
  }

  const acceptRisk = (riskId: string, expiresAt: string, condition: string): void => {
    withCommit((draft) => {
      const risk = draft.risks.find((item) => item.id === riskId)
      if (!risk) return
      risk.status = 'accepted'
      risk.acceptanceExpiresAt = expiresAt
      risk.acceptanceCondition = condition
      appendAudit(draft, 'risk', risk.id, '接受风险', `接受有效至 ${expiresAt}：${condition}`)
    })
  }

  const closeRisk = (riskId: string): void => {
    withCommit((draft) => {
      const risk = draft.risks.find((item) => item.id === riskId)
      if (!risk) return
      risk.status = 'closed'
      appendAudit(draft, 'risk', risk.id, '关闭风险', '风险已关闭并从开放风险中移除')
    })
  }

  const resetDemo = (): void => {
    data.value = resetState()
    lastSavedAt.value = new Date().toISOString()
  }

  const exportReport = (): string => {
    const state = data.value
    const threats = activeThreats(state)
    const lines = [
      `# ${state.boundary.name} 威胁建模报告`,
      '',
      `生成时间：${new Date().toISOString()}`,
      `当前版本：v1.${state.currentRevision}`,
      `建模范围：${state.boundary.inScope}`,
      `排除范围：${state.boundary.outOfScope}`,
      '',
      '## 风险摘要',
      `- 资产与组件：${metrics.value.components}`,
      `- 威胁：${threats.length}`,
      `- 开放关键威胁：${metrics.value.critical}`,
      `- 威胁覆盖率：${metrics.value.coverage}%`,
      `- 待处理校验问题：${issues.value.length}`,
      '',
      '## 威胁清单',
      ...threats.map(
        (threat) =>
          `- ${threat.code} [${threat.severity}/${threat.reviewStatus}] ${threat.title}：${threat.description}`,
      ),
      '',
      '## 风险接受',
      ...state.risks
        .filter((risk) => risk.lifecycle?.status !== 'inactive')
        .filter((risk) => risk.status === 'accepted')
        .map(
          (risk) =>
            `- ${risk.code} ${risk.title}，有效至 ${risk.acceptanceExpiresAt ?? '未设置'}，条件：${risk.acceptanceCondition ?? '未填写'}`,
        ),
      '',
      '## 校验问题',
      ...issues.value.map((issue) => `- [${issue.severity}] ${issue.title}：${issue.detail}`),
      '',
      '## 会签记录',
      ...state.decisions.map(
        (decision) =>
          `- ${decision.createdAt} ${decision.actor}（${decision.role}）${decision.decision}：${decision.comment}`,
      ),
    ]
    return lines.join('\n')
  }

  return {
    data,
    lastSavedAt,
    lastConflict,
    metrics,
    issues,
    pendingReviews,
    interruptedJobs,
    saveEntity,
    updateBoundary,
    saveThreat,
    planCleanup,
    submitCleanup,
    startBatchCleanup,
    resumeCleanupJob,
    dismissCleanupJob,
    createVersion,
    submitDecision,
    updateMitigationStatus,
    acceptRisk,
    closeRisk,
    resetDemo,
    exportReport,
    reviewProgress,
  }
})
