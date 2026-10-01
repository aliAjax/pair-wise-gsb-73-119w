import type {
  LifecycleMeta,
  ReviewStatus,
  ThreatModelState,
} from '@/models/domain'

export type CleanupTargetKind = 'component' | 'flow' | 'dependency'
export type CleanupMode = 'delete' | 'deactivate'
export type CleanupItemKind =
  | 'component'
  | 'flow'
  | 'dependency'
  | 'control'
  | 'evidence'
  | 'threat'
  | 'mitigation'

export interface CleanupPlanItem {
  kind: CleanupItemKind
  id: string
  label: string
  mode: CleanupMode
  reason: string
  cascade: boolean
}

export interface CleanupPlanThreat {
  id: string
  code: string
  title: string
  reviewStatus: ReviewStatus
  /** 草稿威胁：引用被剪除；正式威胁：停用关联对象并回到待重审 */
  action: 'prune_draft' | 'reset_review'
  removedRefs: { kind: string; label: string }[]
}

export interface RemovalPlan {
  targets: { kind: CleanupTargetKind; id: string; label: string; mode: CleanupMode; reason: string }[]
  items: CleanupPlanItem[]
  threats: CleanupPlanThreat[]
  signature: string
  /** 引用内容指纹：引用集合或处置模式变化时改变 */
  fingerprint: string
  generatedAt: string
}

interface TargetRefs {
  threatIds: Set<string>
  flowIds: Set<string>
  controlIds: Set<string>
  evidenceIds: Set<string>
  dependencyIds: Set<string>
}

export const isInactive = (lifecycle?: LifecycleMeta): boolean =>
  lifecycle?.status === 'inactive'

const deactivatedReason = (reason: string): LifecycleMeta => ({
  status: 'inactive',
  deactivatedAt: new Date().toISOString(),
  deactivatedReason: reason,
})

const threatLabel = (state: ThreatModelState, id: string): string => {
  const threat = state.threats.find((item) => item.id === id)
  return threat ? `${threat.code} ${threat.title}` : id
}

const itemLabel = (state: ThreatModelState, kind: CleanupItemKind, id: string): string => {
  switch (kind) {
    case 'component':
      return state.components.find((item) => item.id === id)?.name ?? id
    case 'flow':
      return state.flows.find((item) => item.id === id)?.name ?? id
    case 'dependency':
      return state.dependencies.find((item) => item.id === id)?.name ?? id
    case 'control':
      return state.controls.find((item) => item.id === id)?.name ?? id
    case 'evidence':
      return state.evidence.find((item) => item.id === id)?.title ?? id
    case 'threat':
      return threatLabel(state, id)
    case 'mitigation':
      return state.mitigations.find((item) => item.id === id)?.title ?? id
  }
}

const collectionContains = (state: ThreatModelState, kind: CleanupItemKind, id: string): boolean => {
  switch (kind) {
    case 'component':
      return state.components.some((item) => item.id === id)
    case 'flow':
      return state.flows.some((item) => item.id === id)
    case 'dependency':
      return state.dependencies.some((item) => item.id === id)
    case 'control':
      return state.controls.some((item) => item.id === id)
    case 'evidence':
      return state.evidence.some((item) => item.id === id)
    case 'threat':
      return state.threats.some((item) => item.id === id)
    case 'mitigation':
      return state.mitigations.some((item) => item.id === id)
  }
}

const frozenInVersions = (state: ThreatModelState, kind: CleanupItemKind, id: string): boolean => {
  switch (kind) {
    case 'component':
      return state.versions.some((version) => version.componentIds.includes(id))
    case 'flow':
      return state.versions.some((version) => version.flowIds.includes(id))
    case 'control':
      return state.versions.some((version) => version.controlIds.includes(id))
    case 'threat':
      return state.versions.some((version) => version.threatIds.includes(id))
    default:
      return false
  }
}

const emptyRefs = (): TargetRefs => ({
  threatIds: new Set(),
  flowIds: new Set(),
  controlIds: new Set(),
  evidenceIds: new Set(),
  dependencyIds: new Set(),
})

const collectTargetRefs = (
  state: ThreatModelState,
  kind: CleanupTargetKind,
  id: string,
): TargetRefs => {
  const refs = emptyRefs()
  if (kind === 'component') {
    state.flows.forEach((flow) => {
      if (flow.sourceId === id || flow.targetId === id) refs.flowIds.add(flow.id)
    })
    state.controls.forEach((control) => {
      if (control.componentId === id) refs.controlIds.add(control.id)
    })
  }
  state.threats.forEach((threat) => {
    const hit =
      (kind === 'component' && threat.componentIds.includes(id)) ||
      (kind === 'flow' && threat.flowIds.includes(id)) ||
      (kind === 'dependency' && threat.externalDependencyIds.includes(id))
    if (hit) refs.threatIds.add(threat.id)
  })
  // 控制下的证据通过控制闭包归集，这里不单独扫描
  return refs
}

const unique = <T>(items: T[]): T[] => [...new Set(items)]

const signatureOf = (kind: CleanupTargetKind, id: string): string => `${kind}:${id}`

/**
 * 生成清理前引用核对计划：
 * - 目标对象：仅被草稿威胁引用且无版本冻结 → 物理删除；已冻结或被会签使用 → 停用保留；
 * - 关联流/控制/证据按同一规则级联判定；
 * - 草稿威胁剪除引用，正式威胁关联对象停用并在提交后回到待重审。
 */
export const buildRemovalPlan = (
  state: ThreatModelState,
  targetsInput: { kind: CleanupTargetKind; id: string }[],
): RemovalPlan => {
  // 同名编号去重，已不存在的目标跳过
  const targets = unique(targetsInput.map((target) => `${target.kind}:${target.id}`))
    .map((key) => {
      const [kind, id] = key.split(':') as [CleanupTargetKind, string]
      return { kind, id }
    })
    .filter((target) => collectionContains(state, target.kind, target.id))

  const threatIds = new Set<string>()
  const flowIds = new Set<string>()
  const controlIds = new Set<string>()
  const evidenceIds = new Set<string>()

  const componentTargetIds = new Set(
    targets.filter((target) => target.kind === 'component').map((target) => target.id),
  )

  targets.forEach((target) => {
    const refs = collectTargetRefs(state, target.kind, target.id)
    refs.threatIds.forEach((id) => threatIds.add(id))
    refs.flowIds.forEach((id) => flowIds.add(id))
    refs.controlIds.forEach((id) => controlIds.add(id))
  })

  // 组件被停用时，挂在组件上的流/控制同步停用
  componentTargetIds.forEach((componentId) => {
    state.flows.forEach((flow) => {
      if (flow.sourceId === componentId || flow.targetId === componentId) flowIds.add(flow.id)
    })
    state.controls.forEach((control) => {
      if (control.componentId === componentId) controlIds.add(control.id)
    })
  })

  // 控制闭包带出证据
  controlIds.forEach((controlId) => {
    const control = state.controls.find((item) => item.id === controlId)
    control?.evidenceIds.forEach((evidenceId) => evidenceIds.add(evidenceId))
  })

  const formalThreats = [...threatIds]
    .map((id) => state.threats.find((threat) => threat.id === id))
    .filter((threat): threat is NonNullable<typeof threat> =>
      Boolean(threat && threat.reviewStatus !== 'draft'),
    )
  const formalThreatIds = new Set(formalThreats.map((threat) => threat.id))

  const referencedByFormalThreat = (kind: CleanupItemKind, id: string): boolean => {
    switch (kind) {
      case 'component':
        return state.threats.some(
          (threat) => threat.reviewStatus !== 'draft' && threat.componentIds.includes(id),
        )
      case 'flow':
        return state.threats.some(
          (threat) => threat.reviewStatus !== 'draft' && threat.flowIds.includes(id),
        )
      case 'dependency':
        return state.threats.some(
          (threat) => threat.reviewStatus !== 'draft' && threat.externalDependencyIds.includes(id),
        )
      case 'control':
        return state.threats.some(
          (threat) => threat.reviewStatus !== 'draft' && threat.controlIds.includes(id),
        )
      case 'threat':
        return formalThreatIds.has(id)
      default:
        return false
    }
  }

  const resolveMode = (
    kind: CleanupItemKind,
    id: string,
    opts: { parentDeactivated?: boolean } = {},
  ): CleanupMode => {
    if (opts.parentDeactivated) return 'deactivate'
    if (frozenInVersions(state, kind, id)) return 'deactivate'
    if (referencedByFormalThreat(kind, id)) return 'deactivate'
    return 'delete'
  }

  const reasonFor = (kind: CleanupItemKind, id: string): string => {
    if (frozenInVersions(state, kind, id)) return '该编号已进入版本快照冻结，停用并保留历史。'
    if (referencedByFormalThreat(kind, id)) {
      return '该对象被会签中的威胁使用，停用保留，相关威胁回到待重审。'
    }
    return '仅被草稿引用且未被版本冻结，可从当前版本彻底移除。'
  }

  const targetItems: RemovalPlan['targets'] = targets.map((target) => {
    const mode = resolveMode(target.kind, target.id)
    return {
      kind: target.kind,
      id: target.id,
      label: itemLabel(state, target.kind, target.id),
      mode,
      reason: reasonFor(target.kind, target.id),
    }
  })

  const componentDeactivatedIds = new Set(
    targetItems.filter((item) => item.kind === 'component' && item.mode === 'deactivate').map((item) => item.id),
  )

  // 目标条目
  const itemMap = new Map<string, CleanupPlanItem>()
  const pushItem = (
    kind: CleanupItemKind,
    id: string,
    mode: CleanupMode,
    reason: string,
    cascade: boolean,
  ): void => {
    const key = `${kind}:${id}`
    const existing = itemMap.get(key)
    if (existing) {
      // 同一对象被多个目标带及时，停用（保守策略）优先于删除
      if (existing.mode === 'deactivate' || mode === 'deactivate') {
        itemMap.set(key, {
          ...existing,
          mode: 'deactivate',
          reason: mode === 'deactivate' ? reason : existing.reason,
        })
      }
      return
    }
    itemMap.set(key, { kind, id, label: itemLabel(state, kind, id), mode, reason, cascade })
  }

  targets.forEach((target) => {
    const mode = resolveMode(target.kind, target.id)
    pushItem(target.kind, target.id, mode, reasonFor(target.kind, target.id), false)
  })

  // 级联：流
  flowIds.forEach((flowId) => {
    const flow = state.flows.find((item) => item.id === flowId)
    if (!flow) return
    const parentDown = componentDeactivatedIds.has(flow.sourceId) || componentDeactivatedIds.has(flow.targetId)
    const mode = resolveMode('flow', flowId, { parentDeactivated: parentDown })
    const reason = parentDown
      ? '其端点组件已停用，数据流随之停用保留。'
      : reasonFor('flow', flowId)
    pushItem('flow', flowId, mode, reason, true)
  })

  // 级联：控制
  controlIds.forEach((controlId) => {
    const control = state.controls.find((item) => item.id === controlId)
    if (!control) return
    const parentDown = componentDeactivatedIds.has(control.componentId)
    const mode = resolveMode('control', controlId, { parentDeactivated: parentDown })
    const reason = parentDown
      ? '其归属组件已停用，控制随之停用保留。'
      : reasonFor('control', controlId)
    pushItem('control', controlId, mode, reason, true)
  })

  // 级联：证据——跟随控制；归属控制被彻底删除时，证据无正式引用则一并删除
  const deletedControlIds = new Set(
    [...itemMap.values()].filter((item) => item.kind === 'control' && item.mode === 'delete').map((item) => item.id),
  )
  const deactivatedControlIds = new Set(
    [...itemMap.values()].filter((item) => item.kind === 'control' && item.mode === 'deactivate').map((item) => item.id),
  )
  evidenceIds.forEach((evidenceId) => {
    const evidence = state.evidence.find((item) => item.id === evidenceId)
    if (!evidence) return
    const mode: CleanupMode = deactivatedControlIds.has(evidence.controlId)
      ? 'deactivate'
      : deletedControlIds.has(evidence.controlId)
        ? 'delete'
        : 'delete'
    const reason =
      mode === 'deactivate'
        ? '其归属控制已停用，证据随历史一并保留。'
        : '其归属控制将被移除，证据仅被草稿链路引用，可一并整理。'
    pushItem('evidence', evidenceId, mode, reason, true)
  })

  // 受影响威胁明细
  const refKindLabel = (kind: string): string =>
    ({ component: '组件', flow: '数据流', dependency: '外部依赖', control: '控制', evidence: '证据' })[kind] ?? kind

  const allImpactKeys = new Set<string>([
    ...targets.map((target) => `${target.kind}:${target.id}`),
    ...[...flowIds].map((id) => `flow:${id}`),
    ...[...controlIds].map((id) => `control:${id}`),
  ])

  const threatEntries: CleanupPlanThreat[] = [...threatIds]
    .map((threatId): CleanupPlanThreat | null => {
      const threat = state.threats.find((item) => item.id === threatId)
      if (!threat) return null
      const removedRefs: CleanupPlanThreat['removedRefs'] = []
      threat.componentIds.forEach((id) => {
        if (allImpactKeys.has(`component:${id}`)) {
          removedRefs.push({ kind: refKindLabel('component'), label: itemLabel(state, 'component', id) })
        }
      })
      threat.flowIds.forEach((id) => {
        if (allImpactKeys.has(`flow:${id}`)) {
          removedRefs.push({ kind: refKindLabel('flow'), label: itemLabel(state, 'flow', id) })
        }
      })
      threat.externalDependencyIds.forEach((id) => {
        if (allImpactKeys.has(`dependency:${id}`)) {
          removedRefs.push({ kind: refKindLabel('dependency'), label: itemLabel(state, 'dependency', id) })
        }
      })
      threat.controlIds.forEach((id) => {
        if (allImpactKeys.has(`control:${id}`)) {
          removedRefs.push({ kind: refKindLabel('control'), label: itemLabel(state, 'control', id) })
        }
      })
      return {
        id: threat.id,
        code: threat.code,
        title: threat.title,
        reviewStatus: threat.reviewStatus,
        action: threat.reviewStatus === 'draft' ? 'prune_draft' as const : 'reset_review' as const,
        removedRefs,
      }
    })
    .filter((entry): entry is CleanupPlanThreat => Boolean(entry))

  const signature = targets.map((target) => signatureOf(target.kind, target.id)).sort().join('|')
  // 引用内容指纹：模式（删除/停用）或受影响威胁集合变化都会改变指纹
  const itemFingerprint = [...itemMap.values()]
    .map((item) => `${item.kind}:${item.id}:${item.mode}`)
    .sort()
    .join('|')
  const threatFingerprint = threatEntries
    .map((entry) => `${entry.id}:${entry.action}:${entry.removedRefs.length}`)
    .sort()
    .join('|')

  return {
    targets: targetItems,
    items: [...itemMap.values()],
    threats: threatEntries,
    signature,
    fingerprint: `${signature}#${itemFingerprint}#${threatFingerprint}`,
    generatedAt: new Date().toISOString(),
  }
}

export interface RemovalOutcome {
  deactivated: CleanupPlanItem[]
  deleted: CleanupPlanItem[]
  resetThreatIds: string[]
  prunedDraftThreatIds: string[]
}

/**
 * 按计划原子提交：删除/停用对象、剪除草稿引用、正式威胁回到待重审。
 * 调用方必须在提交前完成乐观锁校验。
 */
export const applyRemovalPlan = (state: ThreatModelState, plan: RemovalPlan): RemovalOutcome => {
  const outcome: RemovalOutcome = {
    deactivated: [],
    deleted: [],
    resetThreatIds: [],
    prunedDraftThreatIds: [],
  }
  const deletedKeys = new Set<string>()
  const deactivatedKeys = new Set<string>()

  const markDeactivated = (
    collection: { id: string; lifecycle?: LifecycleMeta }[],
    id: string,
    reason: string,
  ) => {
    const entity = collection.find((item) => item.id === id)
    if (entity && entity.lifecycle?.status !== 'inactive') {
      entity.lifecycle = deactivatedReason(reason)
    }
  }

  plan.items.forEach((item) => {
    if (item.mode === 'delete') {
      deletedKeys.add(`${item.kind}:${item.id}`)
      outcome.deleted.push(item)
    } else {
      deactivatedKeys.add(`${item.kind}:${item.id}`)
      outcome.deactivated.push(item)
    }
  })

  // 先应用停用，保证剪除引用时正式威胁仍能读到历史对象
  deactivatedKeys.forEach((key) => {
    const [kind, id] = key.split(':') as [CleanupItemKind, string]
    const reason = plan.items.find((item) => item.kind === kind && item.id === id)?.reason ?? '清理时停用保留历史。'
    if (kind === 'component') markDeactivated(state.components, id, reason)
    if (kind === 'flow') markDeactivated(state.flows, id, reason)
    if (kind === 'dependency') markDeactivated(state.dependencies, id, reason)
    if (kind === 'control') markDeactivated(state.controls, id, reason)
    if (kind === 'evidence') markDeactivated(state.evidence, id, reason)
    if (kind === 'threat') markDeactivated(state.threats, id, reason)
    if (kind === 'mitigation') markDeactivated(state.mitigations, id, reason)
  })

  // 草稿威胁：只剪除被彻底删除的引用；停用对象是历史占位，予以保留
  plan.threats.filter((entry) => entry.action === 'prune_draft').forEach((entry) => {
    const threat = state.threats.find((item) => item.id === entry.id)
    if (!threat) return
    const pruneDeleted = (ids: string[], keyPrefix: CleanupItemKind): string[] =>
      ids.filter((id) => !deletedKeys.has(`${keyPrefix}:${id}`))
    const before = {
      componentIds: threat.componentIds.length,
      flowIds: threat.flowIds.length,
      externalDependencyIds: threat.externalDependencyIds.length,
      controlIds: threat.controlIds.length,
    }
    threat.componentIds = pruneDeleted(threat.componentIds, 'component')
    threat.flowIds = pruneDeleted(threat.flowIds, 'flow')
    threat.externalDependencyIds = pruneDeleted(threat.externalDependencyIds, 'dependency')
    threat.controlIds = pruneDeleted(threat.controlIds, 'control')
    const changed =
      before.componentIds !== threat.componentIds.length ||
      before.flowIds !== threat.flowIds.length ||
      before.externalDependencyIds !== threat.externalDependencyIds.length ||
      before.controlIds !== threat.controlIds.length
    if (changed) {
      outcome.prunedDraftThreatIds.push(threat.id)
    }
  })

  // 物理删除（草稿链路独占的对象）
  outcome.deleted.forEach((item) => {
    if (item.kind === 'component') {
      state.components = state.components.filter((entry) => entry.id !== item.id)
    } else if (item.kind === 'flow') {
      state.flows = state.flows.filter((entry) => entry.id !== item.id)
    } else if (item.kind === 'dependency') {
      state.dependencies = state.dependencies.filter((entry) => entry.id !== item.id)
    } else if (item.kind === 'control') {
      state.controls = state.controls.filter((entry) => entry.id !== item.id)
    } else if (item.kind === 'evidence') {
      state.evidence = state.evidence.filter((entry) => entry.id !== item.id)
    }
  })

  // 正式威胁：引用对象已停用/删除的，回到待重审
  // 旧会签意见按 revision 保留为历史，当前修订轮次的未决意见由调用方清除
  plan.threats.filter((entry) => entry.action === 'reset_review').forEach((entry) => {
    const threat = state.threats.find((item) => item.id === entry.id)
    if (!threat) return
    if (entry.removedRefs.length > 0 && threat.reviewStatus !== 'in_review') {
      threat.reviewStatus = 'in_review'
    }
    outcome.resetThreatIds.push(threat.id)
  })

  return outcome
}
