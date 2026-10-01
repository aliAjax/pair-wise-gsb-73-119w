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
  applyCleanupItem,
  buildRemovalPlan,
  type RemovableKind,
  type RemovalPlan,
} from '@/services/cleanup'
import {
  createId,
  loadState,
  migrateState,
  readStoredState,
  resetState,
  saveState,
  STORAGE_KEY,
} from '@/services/repository'
import {
  activeComponents,
  activeDependencies,
  activeEvidence,
  activeFlows,
  activeThreats,
  dashboardMetrics,
  decisionsForThreat,
  getValidationIssues,
  isRetired,
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

export interface CommitResult {
  ok: boolean
  conflict: boolean
}

export interface RemovalResult extends CommitResult {
  plan: RemovalPlan | null
  job: CleanupJob | null
}

const OK: CommitResult = { ok: true, conflict: false }
const CONFLICT: CommitResult = { ok: false, conflict: true }

export const useThreatModelStore = defineStore('threat-model', () => {
  const data = ref<ThreatModelState>(loadState())
  const lastSavedAt = ref(new Date().toISOString())
  /** 其他窗口写入导致的刷新次数（引用关系已变化） */
  const externalSyncCount = ref(0)
  /** 本地提交被并发守卫拒绝的次数 */
  const conflictCount = ref(0)

  const metrics = computed(() => dashboardMetrics(data.value))
  const issues = computed(() => getValidationIssues(data.value))
  const pendingReviews = computed(() =>
    activeThreats(data.value).filter((threat) => threat.reviewStatus === 'in_review'),
  )
  const retiredComponents = computed(() => data.value.components.filter(isRetired))
  const retiredFlows = computed(() => data.value.flows.filter(isRetired))
  const retiredDependencies = computed(() =>
    data.value.dependencies.filter((dependency) => dependency.status === 'retired'),
  )
  /** 中途失败或冲突中断、仍有待处理项的清理任务 */
  const incompleteJobs = computed(() =>
    data.value.cleanupJobs.filter(
      (job) => job.status !== 'done' && job.items.some((item) => item.status === 'pending'),
    ),
  )

  const touchSaved = (): void => {
    lastSavedAt.value = new Date().toISOString()
  }

  const reloadFrom = (stored: ThreatModelState): void => {
    migrateState(stored)
    data.value = stored
    touchSaved()
  }

  /**
   * 乐观并发守卫：提交前比对 localStorage 中的变更计数。
   * 若另一窗口已先提交（移除或重建同一编号），本地未落库的修改被放弃、
   * 状态刷新为最新引用关系，调用方收到 conflict 提示后重试。
   */
  const persist = (): boolean => {
    const stored = readStoredState()
    if (stored && stored.meta.mutationCounter !== data.value.meta.mutationCounter) {
      reloadFrom(stored)
      conflictCount.value += 1
      return false
    }
    data.value.meta.mutationCounter += 1
    saveState(data.value)
    touchSaved()
    return true
  }

  // 跨窗口同步：其他标签页写入 localStorage 时，本窗口立即刷新引用关系
  if (typeof window !== 'undefined') {
    window.addEventListener('storage', (event) => {
      if (event.key !== STORAGE_KEY || !event.newValue) return
      try {
        const incoming = JSON.parse(event.newValue) as ThreatModelState
        if (incoming.meta?.mutationCounter !== data.value.meta.mutationCounter) {
          reloadFrom(incoming)
          externalSyncCount.value += 1
        }
      } catch {
        // 忽略无法解析的外部写入
      }
    })
  }

  const appendAudit = (
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
    data.value.audit.unshift(event)
  }

  const saveEntity = (collection: CollectionKey, item: IdentifiedEntity): CommitResult => {
    const target = data.value[collection] as unknown as IdentifiedEntity[]
    const index = target.findIndex((entry) => entry.id === item.id)
    if (index >= 0) {
      target[index] = item
    } else {
      target.unshift(item)
    }
    const label = 'name' in item && typeof item.name === 'string' ? item.name : item.id
    appendAudit(collection, item.id, index >= 0 ? '更新' : '新增', `${label} 已保存`)
    return persist() ? OK : CONFLICT
  }

  const updateBoundary = (boundary: ThreatModelState['boundary']): CommitResult => {
    data.value.boundary = boundary
    appendAudit('boundary', boundary.id, '更新', `${boundary.name} 的系统边界已更新`)
    return persist() ? OK : CONFLICT
  }

  const saveThreat = (threat: Threat): CommitResult => saveEntity('threats', threat)

  const createVersion = (
    label: string,
    notes: string,
    affectedThreatIds: string[],
  ): VersionSnapshot | null => {
    const revision = data.value.currentRevision + 1
    const snapshot: VersionSnapshot = {
      id: createId('ver'),
      revision,
      label,
      createdAt: new Date().toISOString(),
      author: '当前用户',
      notes,
      threatIds: activeThreats(data.value).map((threat) => threat.id),
      componentIds: activeComponents(data.value).map((component) => component.id),
      flowIds: activeFlows(data.value).map((flow) => flow.id),
      controlIds: data.value.controls.filter((control) => !isRetired(control)).map((c) => c.id),
      riskIds: data.value.risks.map((risk) => risk.id),
      affectedThreatIds,
    }
    data.value.currentRevision = revision
    data.value.versions.unshift(snapshot)
    data.value.threats = data.value.threats.map((threat) => {
      if (!affectedThreatIds.includes(threat.id)) {
        return { ...threat, revision }
      }
      return { ...threat, revision, reviewStatus: 'in_review' }
    })
    appendAudit(
      'version',
      snapshot.id,
      '创建版本',
      `${label} 已创建，${affectedThreatIds.length} 条威胁进入重新审核`,
    )
    if (!persist()) return null
    return snapshot
  }

  const submitDecision = (
    threatId: string,
    role: ActorRole,
    decision: DecisionType,
    actor: string,
    comment: string,
  ): CommitResult => {
    const threat = data.value.threats.find((item) => item.id === threatId)
    if (!threat) return OK
    data.value.decisions = data.value.decisions.filter(
      (item) => !(item.threatId === threatId && item.role === role && item.revision === threat.revision),
    )
    data.value.decisions.unshift({
      id: createId('dec'),
      threatId,
      role,
      actor,
      decision,
      comment,
      createdAt: new Date().toISOString(),
      revision: threat.revision,
    })

    const currentDecisions = decisionsForThreat(data.value.decisions, threatId, threat.revision)
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
      'threat',
      threatId,
      decisionLabel[decision],
      `${actor}（${role}）提交会签意见`,
    )
    return persist() ? OK : CONFLICT
  }

  const updateMitigationStatus = (
    taskId: string,
    status: ThreatModelState['mitigations'][number]['status'],
  ): void => {
    const task = data.value.mitigations.find((item) => item.id === taskId)
    if (!task) return
    task.status = status
    appendAudit('mitigation', task.id, '更新状态', `${task.title} 更新为 ${status}`)
    persist()
  }

  const acceptRisk = (riskId: string, expiresAt: string, condition: string): void => {
    const risk = data.value.risks.find((item) => item.id === riskId)
    if (!risk) return
    risk.status = 'accepted'
    risk.acceptanceExpiresAt = expiresAt
    risk.acceptanceCondition = condition
    appendAudit('risk', risk.id, '接受风险', `接受有效至 ${expiresAt}：${condition}`)
    persist()
  }

  const closeRisk = (riskId: string): void => {
    const risk = data.value.risks.find((item) => item.id === riskId)
    if (!risk) return
    risk.status = 'closed'
    appendAudit('risk', risk.id, '关闭风险', '风险已关闭并从开放风险中移除')
    persist()
  }

  /**
   * 执行清理任务的待处理项：逐项应用、逐项落库。
   * 任一项失败或检测到并发冲突时中断，剩余项保留 pending，等待恢复。
   */
  const runCleanupJob = (jobId: string): CommitResult => {
    const job = data.value.cleanupJobs.find((entry) => entry.id === jobId)
    if (!job) return OK
    job.status = 'running'

    for (const item of job.items) {
      if (item.status !== 'pending') continue
      try {
        applyCleanupItem(data.value, item)
        item.status = 'done'
      } catch (error) {
        item.status = 'failed'
        item.error = error instanceof Error ? error.message : String(error)
        job.status = 'failed'
        appendAudit('cleanup', job.id, '清理中断', `任务项失败：${item.error}，剩余项待恢复`)
        persist()
        return { ok: false, conflict: false }
      }
      if (!persist()) {
        // 并发冲突：状态已刷新为最新，任务保留待恢复项
        return CONFLICT
      }
    }

    job.status = job.items.every((item) => item.status === 'done') ? 'done' : 'failed'
    const retired = job.items.filter((item) => item.kind === 'retire_entity').length
    const deleted = job.items.filter((item) => item.kind === 'delete_entity').length
    const reopened = job.items.filter((item) => item.kind === 'reopen_review').length
    appendAudit(
      'cleanup',
      job.id,
      job.status === 'done' ? '清理完成' : '清理未完成',
      `${job.label}；停用 ${retired} 项、删除 ${deleted} 项、${reopened} 条威胁回到待重审`,
    )
    persist()
    return job.status === 'done' ? OK : { ok: false, conflict: false }
  }

  /** 移除架构实体：先摆出引用关系（计划），任务落库后再逐项执行。 */
  const removeArchitectureEntity = (kind: RemovableKind, id: string): RemovalResult => {
    // 已停用的对象不再重复移除
    if (kind === 'dependency') {
      const dependency = data.value.dependencies.find((entry) => entry.id === id)
      if (!dependency || dependency.status === 'retired') {
        return { ok: false, conflict: false, plan: null, job: null }
      }
    } else {
      const collection = kind === 'component' ? data.value.components : data.value.flows
      const entity = collection.find((entry) => entry.id === id)
      if (!entity || isRetired(entity)) {
        return { ok: false, conflict: false, plan: null, job: null }
      }
    }

    const plan = buildRemovalPlan(data.value, kind, id)
    if (!plan) return { ok: false, conflict: false, plan: null, job: null }

    const job: CleanupJob = {
      id: createId('job'),
      label: plan.label,
      createdAt: new Date().toISOString(),
      status: 'running',
      items: plan.items,
    }
    data.value.cleanupJobs.unshift(job)
    appendAudit('cleanup', job.id, '创建清理任务', plan.label)
    // 任务先落库：执行中途崩溃或冲突时，待处理项不会丢失
    if (!persist()) {
      return { ok: false, conflict: true, plan, job: null }
    }
    const result = runCleanupJob(job.id)
    const persistedJob = data.value.cleanupJobs.find((entry) => entry.id === job.id) ?? null
    return { ...result, plan, job: persistedJob }
  }

  /** 恢复未完成的清理任务（首启自动调用，也可由界面手动触发）。 */
  const resumePendingJobs = (): CommitResult => {
    const resumable = data.value.cleanupJobs.filter(
      (job) =>
        job.status !== 'done' &&
        (job.items.some((item) => item.status === 'pending') ||
          job.items.every((item) => item.status === 'done')),
    )
    for (const job of resumable) {
      const result = runCleanupJob(job.id)
      if (result.conflict) return CONFLICT
      if (!result.ok) return { ok: false, conflict: false }
    }
    return OK
  }

  // 首启恢复：上次中途失败/中断的批量清理，打开页面即续跑未完成项
  resumePendingJobs()

  const resetDemo = (): void => {
    data.value = resetState()
    touchSaved()
  }

  const exportReport = (): string => {
    const components = activeComponents(data.value)
    const flows = activeFlows(data.value)
    const threats = activeThreats(data.value)
    const dependencies = activeDependencies(data.value)
    const evidence = activeEvidence(data.value)
    const retiredLines = [
      ...data.value.components.filter(isRetired).map(
        (component) => `- 组件 ${component.name}（${component.retireReason ?? '已停用'}）`,
      ),
      ...data.value.flows.filter(isRetired).map(
        (flow) => `- 数据流 ${flow.name}（${flow.retireReason ?? '已停用'}）`,
      ),
      ...data.value.controls.filter(isRetired).map(
        (control) => `- 控制 ${control.name}（${control.retireReason ?? '已停用'}）`,
      ),
      ...retiredDependencies.value.map(
        (dependency) => `- 外部依赖 ${dependency.name}（已退役）`,
      ),
    ]
    const lines = [
      `# ${data.value.boundary.name} 威胁建模报告`,
      '',
      `生成时间：${new Date().toISOString()}`,
      `当前版本：v1.${data.value.currentRevision}`,
      `建模范围：${data.value.boundary.inScope}`,
      `排除范围：${data.value.boundary.outOfScope}`,
      '',
      '## 风险摘要',
      `- 资产与组件：${components.length}（停用保留 ${retiredComponents.value.length}）`,
      `- 数据流：${flows.length}（停用保留 ${retiredFlows.value.length}）`,
      `- 外部依赖：${dependencies.length}（退役 ${retiredDependencies.value.length}）`,
      `- 威胁：${threats.length}`,
      `- 控制证据：${evidence.length}`,
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
      ...data.value.risks
        .filter((risk) => risk.status === 'accepted')
        .map(
          (risk) =>
            `- ${risk.code} ${risk.title}，有效至 ${risk.acceptanceExpiresAt ?? '未设置'}，条件：${risk.acceptanceCondition ?? '未填写'}`,
        ),
      '',
      '## 校验问题',
      ...issues.value.map((issue) => `- [${issue.severity}] ${issue.title}：${issue.detail}`),
      '',
      '## 停用对象（保留历史）',
      ...(retiredLines.length > 0 ? retiredLines : ['- 无']),
      '',
      '## 会签记录',
      ...data.value.decisions.map(
        (decision) =>
          `- ${decision.createdAt} ${decision.actor}（${decision.role}）${decision.decision}：${decision.comment}`,
      ),
    ]
    return lines.join('\n')
  }

  return {
    data,
    lastSavedAt,
    externalSyncCount,
    conflictCount,
    metrics,
    issues,
    pendingReviews,
    incompleteJobs,
    saveEntity,
    updateBoundary,
    saveThreat,
    createVersion,
    submitDecision,
    updateMitigationStatus,
    acceptRisk,
    closeRisk,
    removeArchitectureEntity,
    resumePendingJobs,
    resetDemo,
    exportReport,
    reviewProgress,
  }
})
