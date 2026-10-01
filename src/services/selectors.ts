import type {
  ControlEvidence,
  LifecycleMeta,
  ReviewDecision,
  Risk,
  Severity,
  Threat,
  ThreatModelState,
  ValidationIssue,
  VersionDifference,
  VersionSnapshot,
} from '@/models/domain'
import { isInactive } from '@/services/lifecycle'

const TODAY = new Date('2026-09-29T00:00:00+08:00')

export const isActive = (lifecycle?: LifecycleMeta): boolean => !isInactive(lifecycle)

export const activeComponents = (state: ThreatModelState) =>
  state.components.filter((item) => isActive(item.lifecycle))
export const activeFlows = (state: ThreatModelState) =>
  state.flows.filter((item) => isActive(item.lifecycle))
export const activeDependencies = (state: ThreatModelState) =>
  state.dependencies.filter((item) => isActive(item.lifecycle))
export const activeControls = (state: ThreatModelState) =>
  state.controls.filter((item) => isActive(item.lifecycle))
export const activeEvidence = (state: ThreatModelState) =>
  state.evidence.filter((item) => isActive(item.lifecycle))
export const activeThreats = (state: ThreatModelState) =>
  state.threats.filter((item) => isActive(item.lifecycle))
export const activeRisks = (state: ThreatModelState) =>
  state.risks.filter((item) => isActive(item.lifecycle))
export const activeMitigations = (state: ThreatModelState) =>
  state.mitigations.filter((item) => isActive(item.lifecycle))

export const riskScore = (risk: Risk): number => risk.likelihood * risk.impact

export const riskLevel = (score: number): Severity => {
  if (score >= 20) return 'critical'
  if (score >= 12) return 'high'
  if (score >= 6) return 'medium'
  return 'low'
}

export const isExpired = (date?: string): boolean =>
  Boolean(date && new Date(`${date}T23:59:59+08:00`).getTime() < TODAY.getTime())

export const evidenceIsExpired = (evidence: ControlEvidence): boolean => isExpired(evidence.expiresAt)

export const getValidationIssues = (state: ThreatModelState): ValidationIssue[] => {
  const issues: ValidationIssue[] = []
  const components = activeComponents(state)
  const flows = activeFlows(state)
  const controls = activeControls(state)
  const evidence = activeEvidence(state)
  const risks = activeRisks(state)
  const mitigations = activeMitigations(state)
  const threats = activeThreats(state)

  const coveredComponentIds = new Set(threats.flatMap((threat) => threat.componentIds))
  const coveredFlowIds = new Set(threats.flatMap((threat) => threat.flowIds))

  components
    .filter((component) => !coveredComponentIds.has(component.id))
    .forEach((component) => {
      issues.push({
        id: `coverage-component-${component.id}`,
        kind: 'uncovered_component',
        severity: component.criticality,
        title: `${component.name} 尚无关联威胁`,
        detail: '该组件位于建模边界内，但当前威胁清单没有覆盖它。',
        entityId: component.id,
      })
    })

  flows
    .filter((flow) => !coveredFlowIds.has(flow.id))
    .forEach((flow) => {
      issues.push({
        id: `coverage-flow-${flow.id}`,
        kind: 'uncovered_component',
        severity: flow.crossesTrustBoundary ? 'high' : 'medium',
        title: `${flow.name} 尚无关联威胁`,
        detail: '该数据流未进入威胁分析，请确认是否需要补充威胁场景。',
        entityId: flow.id,
      })
    })

  controls
    .filter((control) => control.status === 'failed' || control.status === 'degraded')
    .forEach((control) => {
      issues.push({
        id: `control-${control.id}`,
        kind: 'control_failed',
        severity: control.status === 'failed' ? 'critical' : 'high',
        title: `${control.name} 控制${control.status === 'failed' ? '已失效' : '能力降级'}`,
        detail: '控制状态低于设计目标，相关缓解措施必须重新验证。',
        entityId: control.id,
      })
    })

  controls
    .filter((control) => {
      if (control.evidenceIds.length === 0) return true
      const validEvidenceRecords = control.evidenceIds
        .map((id) => evidence.find((item) => item.id === id))
        .filter((item): item is ControlEvidence => Boolean(item))
        .filter((item) => item.valid && !evidenceIsExpired(item))
      return validEvidenceRecords.length === 0
    })
    .forEach((control) => {
      issues.push({
        id: `evidence-${control.id}`,
        kind: 'missing_evidence',
        severity: control.status === 'planned' ? 'medium' : 'high',
        title: `${control.name} 缺少有效证据`,
        detail: '未找到未过期且状态有效的控制证据，暂不能判定控制持续有效。',
        entityId: control.id,
      })
    })

  risks
    .filter((risk) => risk.status === 'accepted' && isExpired(risk.acceptanceExpiresAt))
    .forEach((risk) => {
      issues.push({
        id: `expired-${risk.id}`,
        kind: 'risk_acceptance_expired',
        severity: riskLevel(riskScore(risk)),
        title: `${risk.code} 风险接受已过期`,
        detail: `接受到期日为 ${risk.acceptanceExpiresAt ?? '未设置'}，需要重新评审或转为处置。`,
        entityId: risk.id,
      })
    })

  // 悬空引用：活动威胁引用了缺失或已停用的对象
  const staleKinds: { key: string; label: string; ids: Set<string> }[] = [
    { key: 'componentIds', label: '组件', ids: new Set(state.components.map((item) => item.id)) },
    { key: 'flowIds', label: '数据流', ids: new Set(state.flows.map((item) => item.id)) },
    { key: 'externalDependencyIds', label: '外部依赖', ids: new Set(state.dependencies.map((item) => item.id)) },
    { key: 'controlIds', label: '控制', ids: new Set(state.controls.map((item) => item.id)) },
    { key: 'attackPathIds', label: '攻击路径', ids: new Set(state.attackPaths.map((item) => item.id)) },
    { key: 'riskIds', label: '风险', ids: new Set(state.risks.map((item) => item.id)) },
  ]
  const inactiveIdSet = (collection: { id: string; lifecycle?: LifecycleMeta }[]) =>
    new Set(collection.filter((item) => !isActive(item.lifecycle)).map((item) => item.id))
  const inactivePools = {
    componentIds: inactiveIdSet(state.components),
    flowIds: inactiveIdSet(state.flows),
    externalDependencyIds: inactiveIdSet(state.dependencies),
    controlIds: inactiveIdSet(state.controls),
    attackPathIds: inactiveIdSet(state.attackPaths),
    riskIds: inactiveIdSet(state.risks),
  }

  threats.forEach((threat) => {
    staleKinds.forEach(({ key, label, ids }) => {
      const refs = (threat as unknown as Record<string, string[]>)[key] ?? []
      const missing = refs.filter((id) => !ids.has(id))
      const stopped = refs.filter((id) =>
        (inactivePools as Record<string, Set<string>>)[key]?.has(id),
      )
      if (missing.length > 0) {
        issues.push({
          id: `stale-${threat.id}-${key}-missing`,
          kind: 'stale_reference',
          severity: 'high',
          title: `${threat.code} 存在缺失的${label}引用`,
          detail: `编号 ${missing.join('、')} 在模型中已不存在，请重新关联或剪除草稿引用。`,
          entityId: threat.id,
        })
      }
      if (stopped.length > 0) {
        issues.push({
          id: `stale-${threat.id}-${key}-inactive`,
          kind: 'stale_reference',
          severity: 'medium',
          title: `${threat.code} 引用了已停用的${label}`,
          detail: `编号 ${stopped.join('、')} 已停用留档，威胁需要重新评估或改挂新对象。`,
          entityId: threat.id,
        })
      }
    })
  })

  const taskGroups = new Map<string, typeof mitigations>()
  mitigations.forEach((task) => {
    if (!task.conflictGroup) return
    const key = `${task.threatId}:${task.conflictGroup}`
    const group = taskGroups.get(key) ?? []
    group.push(task)
    taskGroups.set(key, group)
  })

  taskGroups.forEach((tasks) => {
    const actions = new Set(tasks.map((task) => task.action))
    const hasAllow = actions.has('allow_with_condition')
    const hasRestrictiveAction = actions.has('restrict') || actions.has('isolate')
    if (hasAllow && hasRestrictiveAction) {
      issues.push({
        id: `conflict-${tasks[0]?.conflictGroup ?? 'unknown'}`,
        kind: 'mitigation_conflict',
        severity: 'high',
        title: '缓解措施处置方向冲突',
        detail: tasks.map((task) => task.title).join('；'),
        entityId: tasks[0]?.threatId ?? '',
      })
    }
  })

  return issues.sort((a, b) => {
    const rank: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 }
    return rank[b.severity] - rank[a.severity]
  })
}

export const decisionsForThreat = (
  decisions: ReviewDecision[],
  threatId: string,
  revision: number,
): ReviewDecision[] =>
  decisions.filter((decision) => decision.threatId === threatId && decision.revision === revision)

export const reviewProgress = (decisions: ReviewDecision[]): number => {
  const roles = new Set(decisions.map((decision) => decision.role))
  return Math.round((roles.size / 3) * 100)
}

export const compareSnapshots = (from: VersionSnapshot, to: VersionSnapshot): VersionDifference => {
  const compare = (
    category: string,
    before: string[],
    after: string[],
  ): { added: VersionDifference['added']; removed: VersionDifference['removed'] } => {
    const beforeSet = new Set(before)
    const afterSet = new Set(after)
    return {
      added: after.filter((id) => !beforeSet.has(id)).map((id) => ({ category, id })),
      removed: before.filter((id) => !afterSet.has(id)).map((id) => ({ category, id })),
    }
  }

  const componentDiff = compare('组件', from.componentIds, to.componentIds)
  const flowDiff = compare('数据流', from.flowIds, to.flowIds)
  const threatDiff = compare('威胁', from.threatIds, to.threatIds)
  const controlDiff = compare('控制', from.controlIds, to.controlIds)
  const riskDiff = compare('风险', from.riskIds, to.riskIds)
  const affectedBefore = new Set(from.affectedThreatIds)
  const affectedAfter = new Set(to.affectedThreatIds)

  return {
    added: [
      ...componentDiff.added,
      ...flowDiff.added,
      ...threatDiff.added,
      ...controlDiff.added,
      ...riskDiff.added,
    ],
    removed: [
      ...componentDiff.removed,
      ...flowDiff.removed,
      ...threatDiff.removed,
      ...controlDiff.removed,
      ...riskDiff.removed,
    ],
    changed: [
      `受影响威胁：${from.affectedThreatIds.length} → ${to.affectedThreatIds.length}`,
      `新增进入审核：${[...affectedAfter].filter((id) => !affectedBefore.has(id)).join('、') || '无'}`,
      `退出审核：${[...affectedBefore].filter((id) => !affectedAfter.has(id)).join('、') || '无'}`,
      `版本说明：${to.notes || '未填写'}`,
    ],
  }
}

export const threatCoverage = (state: ThreatModelState): number => {
  const components = activeComponents(state)
  if (components.length === 0) return 100
  const covered = new Set(
    activeThreats(state).flatMap((threat) => threat.componentIds),
  )
  return Math.round((covered.size / components.length) * 100)
}

export const openCriticalThreats = (threats: Threat[]): number =>
  threats
    .filter((threat) => isActive(threat.lifecycle))
    .filter((threat) => threat.severity === 'critical' && threat.status !== 'mitigated').length

export interface DashboardMetrics {
  components: number
  threats: number
  critical: number
  coverage: number
  openIssues: number
  pendingReviews: number
}

export const dashboardMetrics = (state: ThreatModelState): DashboardMetrics => {
  const threats = activeThreats(state)
  return {
    components: activeComponents(state).length,
    threats: threats.length,
    critical: openCriticalThreats(threats),
    coverage: threatCoverage(state),
    openIssues: getValidationIssues(state).length,
    pendingReviews: threats.filter((threat) => threat.reviewStatus === 'in_review').length,
  }
}
