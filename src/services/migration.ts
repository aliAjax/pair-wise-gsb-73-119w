import type {
  ArchitectureComponent,
  DataFlow,
  ExternalDependency,
  LifecycleStatus,
  SecurityControl,
  ThreatModelState,
} from '@/models/domain'

const CURRENT_SCHEMA_VERSION = 2
const randomToken = (): string =>
  `dv-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`

const deactivated = (reason: string) => ({
  status: 'inactive' as LifecycleStatus,
  deactivatedAt: '2026-09-29T00:00:00+08:00',
  deactivatedReason: reason,
})

const activeMeta = () => ({ status: 'active' as LifecycleStatus })

const ensureLifecycle = <T extends { lifecycle?: { status?: LifecycleStatus } }>(items: T[]): void => {
  items.forEach((item) => {
    if (!item.lifecycle) item.lifecycle = activeMeta()
  })
}

/**
 * 旧数据迁移：
 * 1. 补齐生命周期标记（历史对象默认活动）；
 * 2. 修复悬空引用——已被版本快照冻结的编号补建“停用”占位对象保留历史，
 *    未冻结的引用直接从活动对象上剪除；
 * 3. 补齐批量清理任务、版本号与乐观锁令牌。
 */
export const migrateState = (raw: unknown): ThreatModelState => {
  const state = structuredClone(raw) as ThreatModelState

  if (!state.boundary || !Array.isArray(state.components)) {
    throw new Error('不可识别的模型数据')
  }

  state.zones = state.zones ?? []
  state.components = state.components ?? []
  state.dependencies = state.dependencies ?? []
  state.flows = state.flows ?? []
  state.controls = state.controls ?? []
  state.evidence = state.evidence ?? []
  state.threats = state.threats ?? []
  state.attackPaths = state.attackPaths ?? []
  state.risks = state.risks ?? []
  state.mitigations = state.mitigations ?? []
  state.decisions = state.decisions ?? []
  state.versions = state.versions ?? []
  state.audit = state.audit ?? []
  state.cleanupJobs = state.cleanupJobs ?? []
  state.currentRevision = state.currentRevision ?? state.versions.length

  // 崩溃窗口内遗留的 running 任务恢复为 interrupted，等待人工续跑
  state.cleanupJobs.forEach((job) => {
    if (job.status === 'running') {
      job.status = 'interrupted'
      job.lastError = job.lastError ?? '批量处理在提交中断，等待恢复未完成项。'
    }
    job.completedSignatures = job.completedSignatures ?? []
    job.failedSignatures = job.failedSignatures ?? []
  })

  const frozen = {
    components: new Set(state.versions.flatMap((version) => version.componentIds ?? [])),
    flows: new Set(state.versions.flatMap((version) => version.flowIds ?? [])),
    controls: new Set(state.versions.flatMap((version) => version.controlIds ?? [])),
    risks: new Set(state.versions.flatMap((version) => version.riskIds ?? [])),
    threats: new Set(state.versions.flatMap((version) => version.threatIds ?? [])),
  }
  const nonDraftThreats = state.threats.filter((threat) => threat.reviewStatus !== 'draft')
  const usedComponents = new Set(nonDraftThreats.flatMap((threat) => threat.componentIds))
  const usedFlows = new Set(nonDraftThreats.flatMap((threat) => threat.flowIds))
  const usedDeps = new Set(nonDraftThreats.flatMap((threat) => threat.externalDependencyIds))
  const usedPaths = new Set(nonDraftThreats.flatMap((threat) => threat.attackPathIds))
  const usedControls = new Set(nonDraftThreats.flatMap((threat) => threat.controlIds))
  const usedRisks = new Set(nonDraftThreats.flatMap((threat) => threat.riskIds))

  // ---- 组件：冻结编号或被正式威胁引用的悬空编号补占位 ----
  const componentIds = new Set(state.components.map((item) => item.id))
  const missingComponentIds = new Set<string>([
    ...frozen.components,
    ...usedComponents,
    ...state.controls.map((control) => control.componentId),
    ...state.flows.flatMap((flow) => [flow.sourceId, flow.targetId]),
  ])
  missingComponentIds.forEach((id) => {
    if (!id || componentIds.has(id)) return
    const placeholder: ArchitectureComponent = {
      id,
      name: `已删除组件（${id}）`,
      type: 'asset',
      zoneId: state.zones[0]?.id ?? '',
      criticality: 'medium',
      owner: '系统迁移',
      description: '旧数据迁移时补建的停用占位对象，仅用于保留版本与报告中的历史编号。',
      lifecycle: deactivated('迁移补建：原始组件已在旧版本中删除，但编号仍被版本或正式威胁引用。'),
    }
    state.components.push(placeholder)
    componentIds.add(id)
  })

  // ---- 数据流 ----
  const flowIds = new Set(state.flows.map((item) => item.id))
  new Set<string>([...frozen.flows, ...usedFlows]).forEach((id) => {
    if (!id || flowIds.has(id)) return
    const placeholder: DataFlow = {
      id,
      name: `已删除数据流（${id}）`,
      sourceId: '',
      targetId: '',
      protocol: '-',
      dataClass: 'internal',
      crossesTrustBoundary: false,
      description: '旧数据迁移时补建的停用占位对象，仅用于保留版本与报告中的历史编号。',
      lifecycle: deactivated('迁移补建：原始数据流已在旧版本中删除，但编号仍被版本或正式威胁引用。'),
    }
    state.flows.push(placeholder)
    flowIds.add(id)
  })

  // ---- 外部依赖（版本快照不登记，依据正式威胁引用判定） ----
  const dependencyIds = new Set(state.dependencies.map((item) => item.id))
  usedDeps.forEach((id) => {
    if (!id || dependencyIds.has(id)) return
    const placeholder: ExternalDependency = {
      id,
      name: `已删除外部依赖（${id}）`,
      vendor: '未知',
      purpose: '迁移补建的历史占位',
      dataClass: 'internal',
      owner: '系统迁移',
      status: 'retired',
      lifecycle: deactivated('迁移补建：依赖已删除但仍被正式威胁引用。'),
    }
    state.dependencies.push(placeholder)
    dependencyIds.add(id)
  })

  // ---- 控制 ----
  const controlIds = new Set(state.controls.map((item) => item.id))
  new Set<string>([...frozen.controls, ...usedControls]).forEach((id) => {
    if (!id || controlIds.has(id)) return
    const placeholder: SecurityControl = {
      id,
      name: `已删除控制（${id}）`,
      type: 'preventive',
      status: 'planned',
      owner: '系统迁移',
      componentId: '',
      description: '旧数据迁移时补建的停用占位对象，仅用于保留版本与报告中的历史编号。',
      evidenceIds: [],
      lifecycle: deactivated('迁移补建：控制已删除但编号仍被版本或正式威胁引用。'),
    }
    state.controls.push(placeholder)
    controlIds.add(id)
  })

  // ---- 风险 ----
  const riskIds = new Set(state.risks.map((item) => item.id))
  new Set<string>([...frozen.risks, ...usedRisks]).forEach((id) => {
    if (!id || riskIds.has(id)) return
    state.risks.push({
      id,
      code: `RSK-${id}`,
      title: `已删除风险（${id}）`,
      likelihood: 1,
      impact: 1,
      status: 'closed',
      owner: '系统迁移',
      lifecycle: deactivated('迁移补建：风险已删除但编号仍被版本或正式威胁引用。'),
    })
    riskIds.add(id)
  })

  // ---- 攻击路径 ----
  const pathIds = new Set(state.attackPaths.map((item) => item.id))
  usedPaths.forEach((id) => {
    if (!id || pathIds.has(id)) return
    state.attackPaths.push({
      id,
      name: `已删除攻击路径（${id}）`,
      entryPoint: '-',
      target: '-',
      steps: [],
      likelihood: 1,
      lifecycle: deactivated('迁移补建：攻击路径已删除但仍被正式威胁引用。'),
    })
    pathIds.add(id)
  })

  // ---- 证据：悬空的证据按其归属处理 ----
  const validControlIds = new Set(state.controls.map((item) => item.id))
  state.evidence.forEach((evidence) => {
    if (!validControlIds.has(evidence.controlId)) {
      evidence.lifecycle = deactivated('迁移补建：归属控制已不存在，证据停用留档。')
    }
  })
  const evidenceIds = new Set(state.evidence.map((item) => item.id))

  // ---- 缓解任务：威胁悬空的停用保留 ----
  const validThreatIds = new Set(state.threats.map((item) => item.id))
  state.mitigations.forEach((task) => {
    if (!validThreatIds.has(task.threatId)) {
      task.lifecycle = deactivated('迁移补建：关联威胁已不存在，任务停用留档。')
    }
    task.evidenceIds = task.evidenceIds.filter((id) => evidenceIds.has(id))
  })

  // ---- 数据流端点：不存在的端点剪除（端点占位已在组件阶段补齐） ----
  state.flows.forEach((flow) => {
    if (flow.sourceId && !componentIds.has(flow.sourceId)) flow.sourceId = ''
    if (flow.targetId && !componentIds.has(flow.targetId)) flow.targetId = ''
  })

  // ---- 控制归属 ----
  state.controls.forEach((control) => {
    if (control.componentId && !componentIds.has(control.componentId)) control.componentId = ''
    control.evidenceIds = control.evidenceIds.filter((id) => evidenceIds.has(id))
  })

  // ---- 威胁自身的悬空引用 ----
  state.threats.forEach((threat) => {
    threat.componentIds = threat.componentIds.filter((id) => componentIds.has(id))
    threat.flowIds = threat.flowIds.filter((id) => flowIds.has(id))
    threat.externalDependencyIds = threat.externalDependencyIds.filter((id) => dependencyIds.has(id))
    threat.attackPathIds = threat.attackPathIds.filter((id) => pathIds.has(id))
    threat.controlIds = threat.controlIds.filter((id) => controlIds.has(id))
    threat.riskIds = threat.riskIds.filter((id) => riskIds.has(id))
  })

  // ---- 快照编号去重（防御性） ----
  state.versions.forEach((version) => {
    version.threatIds = [...new Set(version.threatIds ?? [])]
    version.componentIds = [...new Set(version.componentIds ?? [])]
    version.flowIds = [...new Set(version.flowIds ?? [])]
    version.controlIds = [...new Set(version.controlIds ?? [])]
    version.riskIds = [...new Set(version.riskIds ?? [])]
    version.affectedThreatIds = version.affectedThreatIds ?? []
  })

  ensureLifecycle(state.components)
  ensureLifecycle(state.dependencies)
  ensureLifecycle(state.flows)
  ensureLifecycle(state.controls)
  ensureLifecycle(state.evidence)
  ensureLifecycle(state.attackPaths)
  ensureLifecycle(state.risks)
  ensureLifecycle(state.threats)
  ensureLifecycle(state.mitigations)

  state.schemaVersion = CURRENT_SCHEMA_VERSION
  if (!state.dataVersion) state.dataVersion = randomToken()

  return state
}

export const needsMigration = (raw: unknown): boolean => {
  const candidate = raw as { schemaVersion?: number } | null
  return !candidate || candidate.schemaVersion !== CURRENT_SCHEMA_VERSION
}
