import type {
  CleanupEntityCollection,
  CleanupJobItem,
  Threat,
  ThreatModelState,
} from '@/models/domain'
import { createId } from '@/services/repository'

export type RemovableKind = 'component' | 'flow' | 'dependency'

export const REMOVABLE_COLLECTION: Record<RemovableKind, CleanupEntityCollection> = {
  component: 'components',
  flow: 'flows',
  dependency: 'dependencies',
}

export const REMOVABLE_LABEL: Record<RemovableKind, string> = {
  component: '组件',
  flow: '数据流',
  dependency: '外部依赖',
}

export interface EntityDisposition {
  collection: CleanupEntityCollection
  id: string
  name: string
  disposition: 'delete' | 'retire'
  reason: string
}

export interface ThreatDisposition {
  threatId: string
  code: string
  title: string
  /** strip：草稿仅解除引用；delete：草稿腾空后一并删除；reopen：解除引用并回到待重审 */
  disposition: 'strip' | 'delete' | 'reopen'
  reason: string
}

/** 移除影响分析：对话框预览与实际执行共用同一份结果，保证所见即所得。 */
export interface RemovalPlan {
  kind: RemovableKind
  targetId: string
  targetName: string
  targetDisposition: 'delete' | 'retire'
  targetReason: string
  cascade: EntityDisposition[]
  threats: ThreatDisposition[]
  evidenceCascade: EntityDisposition[]
  versionLabels: string[]
  decisionCount: number
  mitigationDeleteCount: number
  items: CleanupJobItem[]
  label: string
}

const threatHasDecisions = (state: ThreatModelState, threatId: string): boolean =>
  state.decisions.some((decision) => decision.threatId === threatId)

/** 会签使用 = 非草稿状态，或任意修订上已存在会签意见。 */
const threatSignoffUsed = (state: ThreatModelState, threat: Threat): boolean =>
  threat.reviewStatus !== 'draft' || threatHasDecisions(state, threat.id)

const THREAT_REF_FIELD: Partial<Record<CleanupEntityCollection, keyof Threat>> = {
  components: 'componentIds',
  flows: 'flowIds',
  dependencies: 'externalDependencyIds',
  controls: 'controlIds',
}

const versionFreezeCount = (
  state: ThreatModelState,
  collection: CleanupEntityCollection,
  id: string,
): number =>
  state.versions.filter((version) => {
    if (collection === 'components') return version.componentIds.includes(id)
    if (collection === 'flows') return version.flowIds.includes(id)
    if (collection === 'controls') return version.controlIds.includes(id)
    return false
  }).length

interface DirectEntity {
  collection: CleanupEntityCollection
  id: string
  name: string
}

const entityName = (state: ThreatModelState, collection: CleanupEntityCollection, id: string): string => {
  const list = state[collection] as unknown as Array<{ id: string; name?: string; title?: string; code?: string }>
  const entity = list.find((entry) => entry.id === id)
  if (!entity) return id
  return entity.name ?? entity.title ?? entity.code ?? id
}

/**
 * 计算移除计划：先把引用关系全部摆出来，再按
 * 「只被草稿引用 → 一并整理；被版本冻结或会签使用 → 停用保留历史」分类。
 */
export const buildRemovalPlan = (
  state: ThreatModelState,
  kind: RemovableKind,
  targetId: string,
): RemovalPlan | null => {
  const targetCollection = REMOVABLE_COLLECTION[kind]
  const targetList = state[targetCollection] as unknown as Array<{ id: string }>
  if (!targetList.some((entry) => entry.id === targetId)) return null

  const targetName = entityName(state, targetCollection, targetId)

  // 1. 直接受影响的实体：目标本身 + 级联（组件带出其上控制与其两端数据流）
  const direct: DirectEntity[] = [{ collection: targetCollection, id: targetId, name: targetName }]
  if (kind === 'component') {
    state.controls
      .filter((control) => control.componentId === targetId)
      .forEach((control) =>
        direct.push({ collection: 'controls', id: control.id, name: control.name }),
      )
    state.flows
      .filter((flow) => flow.sourceId === targetId || flow.targetId === targetId)
      .forEach((flow) => direct.push({ collection: 'flows', id: flow.id, name: flow.name }))
  }

  // 2. 每个实体的引用威胁与冻结原因
  const referencingThreats = (entity: DirectEntity): Threat[] => {
    const field = THREAT_REF_FIELD[entity.collection]
    if (!field) return []
    return state.threats.filter((threat) => (threat[field] as string[]).includes(entity.id))
  }

  const entityDispositionOf = (entity: DirectEntity): EntityDisposition => {
    const frozenVersions = versionFreezeCount(state, entity.collection, entity.id)
    const signoffThreats = referencingThreats(entity).filter((threat) =>
      threatSignoffUsed(state, threat),
    )
    if (frozenVersions > 0 || signoffThreats.length > 0) {
      const reasons: string[] = []
      if (frozenVersions > 0) reasons.push(`被 ${frozenVersions} 个版本快照冻结`)
      if (signoffThreats.length > 0) reasons.push(`被 ${signoffThreats.length} 条会签威胁引用`)
      return {
        collection: entity.collection,
        id: entity.id,
        name: entity.name,
        disposition: 'retire',
        reason: `${reasons.join('、')}，转停用保留历史`,
      }
    }
    return {
      collection: entity.collection,
      id: entity.id,
      name: entity.name,
      disposition: 'delete',
      reason: '仅被草稿引用，随清理一并移除',
    }
  }

  const dispositions = direct.map(entityDispositionOf)
  const dispositionById = new Map(dispositions.map((entry) => [entry.id, entry]))
  const targetDisposition = dispositionById.get(targetId)?.disposition ?? 'delete'
  const targetReason = dispositionById.get(targetId)?.reason ?? ''

  // 3. 受影响威胁：引用了任意直接实体
  const affectedThreatIds = new Set<string>()
  direct.forEach((entity) =>
    referencingThreats(entity).forEach((threat) => affectedThreatIds.add(threat.id)),
  )

  const removedIdsByField = new Map<keyof Threat, Set<string>>(
    (['componentIds', 'flowIds', 'externalDependencyIds', 'controlIds'] as Array<keyof Threat>).map(
      (field) => [
        field,
        new Set(
          direct
            .filter((entity) => THREAT_REF_FIELD[entity.collection] === field)
            .map((entity) => entity.id),
        ),
      ],
    ),
  )

  const threats: ThreatDisposition[] = [...affectedThreatIds].map((threatId) => {
    const threat = state.threats.find((entry) => entry.id === threatId) as Threat
    if (threatSignoffUsed(state, threat)) {
      return {
        threatId,
        code: threat.code,
        title: threat.title,
        disposition: 'reopen',
        reason: '解除引用后回到待重审，历史会签意见保留',
      }
    }
    const anchored =
      threat.componentIds.some((id) => !removedIdsByField.get('componentIds')?.has(id)) ||
      threat.flowIds.some((id) => !removedIdsByField.get('flowIds')?.has(id))
    return anchored
      ? {
          threatId,
          code: threat.code,
          title: threat.title,
          disposition: 'strip',
          reason: '草稿威胁，仅解除失效引用',
        }
      : {
          threatId,
          code: threat.code,
          title: threat.title,
          disposition: 'delete',
          reason: '草稿威胁失去全部组件与数据流锚点，一并删除',
        }
  })

  const deletedThreatIds = new Set(
    threats.filter((entry) => entry.disposition === 'delete').map((entry) => entry.threatId),
  )

  // 4. 级联：被删威胁的缓解任务、被删控制的证据
  const mitigationDeleteIds = state.mitigations
    .filter((task) => deletedThreatIds.has(task.threatId))
    .map((task) => task.id)

  const deletedControlIds = new Set(
    dispositions
      .filter((entry) => entry.collection === 'controls' && entry.disposition === 'delete')
      .map((entry) => entry.id),
  )
  const retiredControlIds = new Set(
    dispositions
      .filter((entry) => entry.collection === 'controls' && entry.disposition === 'retire')
      .map((entry) => entry.id),
  )
  const evidenceCascade: EntityDisposition[] = state.evidence
    .filter((item) => deletedControlIds.has(item.controlId) || retiredControlIds.has(item.controlId))
    .map((item) => {
      const retiring = retiredControlIds.has(item.controlId)
      return {
        collection: 'evidence' as const,
        id: item.id,
        name: item.title,
        disposition: retiring ? ('retire' as const) : ('delete' as const),
        reason: retiring ? '所属控制停用，证据一并停用' : '所属控制被移除，证据一并清理',
      }
    })
  const clearedEvidenceIds = new Set(evidenceCascade.map((entry) => entry.id))

  // 5. 版本与决策统计（用于对话框展示）
  const versionLabels = state.versions
    .filter((version) =>
      direct.some(
        (entity) =>
          (entity.collection === 'components' && version.componentIds.includes(entity.id)) ||
          (entity.collection === 'flows' && version.flowIds.includes(entity.id)) ||
          (entity.collection === 'controls' && version.controlIds.includes(entity.id)),
      ),
    )
    .map((version) => version.label)
  const decisionCount = state.decisions.filter((decision) =>
    affectedThreatIds.has(decision.threatId),
  ).length

  // 6. 生成批量任务项（顺序即执行顺序，逐项落库可断点恢复）
  const items: CleanupJobItem[] = []
  const push = (
    kind: CleanupJobItem['kind'],
    collection: CleanupEntityCollection,
    entityId: string,
    extra?: Partial<CleanupJobItem>,
  ): void => {
    items.push({
      id: createId('item'),
      kind,
      collection,
      entityId,
      status: 'pending',
      ...extra,
    })
  }

  threats
    .filter((entry) => entry.disposition !== 'delete')
    .forEach((entry) => {
      const threat = state.threats.find((candidate) => candidate.id === entry.threatId) as Threat
      removedIdsByField.forEach((ids, field) => {
        ;(threat[field] as string[])
          .filter((id) => ids.has(id))
          .forEach((id) =>
            push('strip_reference', 'threats', threat.id, {
              field: field as string,
              targetId: id,
              note: `解除 ${threat.code} 对 ${id} 的引用`,
            }),
          )
      })
    })
  threats
    .filter((entry) => entry.disposition === 'reopen')
    .forEach((entry) =>
      push('reopen_review', 'threats', entry.threatId, { note: '相关会签回到待重审' }),
    )
  threats
    .filter((entry) => entry.disposition === 'delete')
    .forEach((entry) => push('delete_entity', 'threats', entry.threatId, { note: entry.reason }))
  mitigationDeleteIds.forEach((id) =>
    push('delete_entity', 'mitigations', id, { note: '所属草稿威胁被删除' }),
  )
  state.mitigations.forEach((task) => {
    task.evidenceIds
      .filter((id) => clearedEvidenceIds.has(id))
      .forEach((id) =>
        push('strip_reference', 'mitigations', task.id, {
          field: 'evidenceIds',
          targetId: id,
          note: '解除缓解任务对已清理证据的引用',
        }),
      )
  })
  evidenceCascade.forEach((entry) =>
    push(entry.disposition === 'retire' ? 'retire_entity' : 'delete_entity', 'evidence', entry.id, {
      note: entry.reason,
    }),
  )
  dispositions
    .filter((entry) => entry.id !== targetId)
    .forEach((entry) =>
      push(
        entry.disposition === 'retire' ? 'retire_entity' : 'delete_entity',
        entry.collection,
        entry.id,
        { note: entry.reason },
      ),
    )
  push(
    targetDisposition === 'retire' ? 'retire_entity' : 'delete_entity',
    targetCollection,
    targetId,
    { note: targetReason },
  )

  return {
    kind,
    targetId,
    targetName,
    targetDisposition,
    targetReason,
    cascade: dispositions.filter((entry) => entry.id !== targetId),
    threats,
    evidenceCascade,
    versionLabels,
    decisionCount,
    mitigationDeleteCount: mitigationDeleteIds.length,
    items,
    label: `清理${REMOVABLE_LABEL[kind]}「${targetName}」：${
      targetDisposition === 'retire' ? '停用保留历史' : '直接移除'
    }，影响 ${threats.length} 条威胁`,
  }
}

/** 应用单个任务项。重复应用安全（幂等），目标已不存在时按完成处理。 */
export const applyCleanupItem = (state: ThreatModelState, item: CleanupJobItem): void => {
  if (item.kind === 'strip_reference') {
    if (!item.field || !item.targetId) return
    const list = state[item.collection] as unknown as Array<Record<string, unknown> & { id: string }>
    const entity = list.find((entry) => entry.id === item.entityId)
    if (!entity) return
    const value = entity[item.field]
    if (Array.isArray(value)) {
      entity[item.field] = value.filter((id) => id !== item.targetId)
    }
    return
  }

  if (item.kind === 'delete_entity') {
    const list = state[item.collection] as unknown as Array<{ id: string }>
    const index = list.findIndex((entry) => entry.id === item.entityId)
    if (index >= 0) list.splice(index, 1)
    return
  }

  if (item.kind === 'retire_entity') {
    const list = state[item.collection] as unknown as Array<
      Record<string, unknown> & { id: string }
    >
    const entity = list.find((entry) => entry.id === item.entityId)
    if (!entity) return
    if (item.collection === 'dependencies') {
      entity.status = 'retired'
    } else {
      entity.lifecycle = 'retired'
      entity.retiredAt = new Date().toISOString()
      entity.retireReason = item.note ?? '架构清理停用'
    }
    return
  }

  if (item.kind === 'reopen_review') {
    const threat = state.threats.find((entry) => entry.id === item.entityId)
    if (!threat) return
    // 引用已变化：当前修订上的会签意见归档为历史，新一轮会签重新开始
    threat.revision += 1
    threat.reviewStatus = 'in_review'
    // 纳入当前版本的会签范围，会签中心才能看到这条待重审威胁
    const latest = state.versions[0]
    if (latest && !latest.affectedThreatIds.includes(threat.id)) {
      latest.affectedThreatIds.push(threat.id)
    }
  }
}
