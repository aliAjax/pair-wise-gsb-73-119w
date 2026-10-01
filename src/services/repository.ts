import type { Retirable, ThreatModelState } from '@/models/domain'
import { createSeedState } from '@/models/seed'

export const STORAGE_KEY = 'scapex-threat-model-v1'
export const SCHEMA_VERSION = 2

export const createId = (prefix: string): string =>
  `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`

/**
 * 旧数据首启迁移：
 * 1. 补齐 meta（模式版本、变更计数器）与清理任务队列；
 * 2. 补齐各实体的生命周期标记；
 * 3. 清理悬空引用，对失去宿主的控制/数据流/证据/任务补停用标记。
 * 返回迁移说明，非空时表示数据被修改、需要落库。
 */
export const migrateState = (state: ThreatModelState): string[] => {
  const fixes: string[] = []

  if (!state.meta || typeof state.meta.mutationCounter !== 'number') {
    state.meta = { schemaVersion: SCHEMA_VERSION, mutationCounter: 0 }
    fixes.push('补充持久化元信息与并发计数器')
  } else {
    state.meta.schemaVersion = SCHEMA_VERSION
  }
  if (!Array.isArray(state.cleanupJobs)) {
    state.cleanupJobs = []
    fixes.push('补充清理任务队列')
  }

  const ensureLifecycle = (entity: Retirable): void => {
    if (entity.lifecycle !== 'active' && entity.lifecycle !== 'retired') {
      entity.lifecycle = 'active'
    }
  }
  state.components.forEach(ensureLifecycle)
  state.flows.forEach(ensureLifecycle)
  state.controls.forEach(ensureLifecycle)
  state.evidence.forEach(ensureLifecycle)
  state.threats.forEach(ensureLifecycle)
  state.mitigations.forEach(ensureLifecycle)

  const componentIds = new Set(state.components.map((component) => component.id))
  const flowIds = new Set(state.flows.map((flow) => flow.id))
  const dependencyIds = new Set(state.dependencies.map((dependency) => dependency.id))
  const controlIds = new Set(state.controls.map((control) => control.id))
  const evidenceIds = new Set(state.evidence.map((item) => item.id))
  const threatIds = new Set(state.threats.map((threat) => threat.id))
  const attackPathIds = new Set(state.attackPaths.map((path) => path.id))
  const riskIds = new Set(state.risks.map((risk) => risk.id))

  const prune = (holder: string, ids: string[], valid: Set<string>): string[] => {
    const kept = ids.filter((id) => valid.has(id))
    if (kept.length !== ids.length) {
      fixes.push(`${holder} 清理 ${ids.length - kept.length} 个悬空引用`)
    }
    return kept
  }

  state.threats.forEach((threat) => {
    threat.componentIds = prune(`威胁 ${threat.code}`, threat.componentIds, componentIds)
    threat.flowIds = prune(`威胁 ${threat.code}`, threat.flowIds, flowIds)
    threat.externalDependencyIds = prune(
      `威胁 ${threat.code}`,
      threat.externalDependencyIds,
      dependencyIds,
    )
    threat.attackPathIds = prune(`威胁 ${threat.code}`, threat.attackPathIds, attackPathIds)
    threat.controlIds = prune(`威胁 ${threat.code}`, threat.controlIds, controlIds)
    threat.riskIds = prune(`威胁 ${threat.code}`, threat.riskIds, riskIds)
  })

  const retire = (entity: Retirable, reason: string): void => {
    entity.lifecycle = 'retired'
    entity.retiredAt = entity.retiredAt ?? new Date().toISOString()
    entity.retireReason = reason
  }

  state.controls.forEach((control) => {
    control.evidenceIds = prune(`控制 ${control.name}`, control.evidenceIds, evidenceIds)
    if (!componentIds.has(control.componentId) && control.lifecycle !== 'retired') {
      retire(control, '所属组件缺失，迁移时停用')
      fixes.push(`控制 ${control.name} 所属组件缺失，已转停用`)
    }
  })

  state.flows.forEach((flow) => {
    const endpointsMissing =
      !componentIds.has(flow.sourceId) || !componentIds.has(flow.targetId)
    if (endpointsMissing && flow.lifecycle !== 'retired') {
      retire(flow, '端点组件缺失，迁移时停用')
      fixes.push(`数据流 ${flow.name} 端点组件缺失，已转停用`)
    }
  })

  state.evidence.forEach((item) => {
    if (!controlIds.has(item.controlId) && item.lifecycle !== 'retired') {
      retire(item, '所属控制缺失，迁移时停用')
      item.valid = false
      fixes.push(`证据 ${item.title} 所属控制缺失，已转停用`)
    }
  })

  state.mitigations.forEach((task) => {
    task.evidenceIds = prune(`缓解任务 ${task.title}`, task.evidenceIds, evidenceIds)
    if (!threatIds.has(task.threatId) && task.lifecycle !== 'retired') {
      retire(task, '所属威胁缺失，迁移时停用')
      fixes.push(`缓解任务 ${task.title} 所属威胁缺失，已转停用`)
    }
  })

  // 第二遍：活跃对象解除对已停用对象的引用，保证图谱、汇总与报告口径一致
  const retiredComponentIds = new Set(
    state.components.filter((item) => item.lifecycle === 'retired').map((item) => item.id),
  )
  const retiredFlowIds = new Set(
    state.flows.filter((item) => item.lifecycle === 'retired').map((item) => item.id),
  )
  const retiredControlIds = new Set(
    state.controls.filter((item) => item.lifecycle === 'retired').map((item) => item.id),
  )
  const retiredEvidenceIds = new Set(
    state.evidence.filter((item) => item.lifecycle === 'retired').map((item) => item.id),
  )
  const retiredDependencyIds = new Set(
    state.dependencies.filter((item) => item.status === 'retired').map((item) => item.id),
  )
  const pruneRetired = (holder: string, ids: string[], retired: Set<string>): string[] => {
    const kept = ids.filter((id) => !retired.has(id))
    if (kept.length !== ids.length) {
      fixes.push(`${holder} 解除 ${ids.length - kept.length} 个对已停用对象的引用`)
    }
    return kept
  }

  state.threats
    .filter((threat) => threat.lifecycle !== 'retired')
    .forEach((threat) => {
      threat.componentIds = pruneRetired(`威胁 ${threat.code}`, threat.componentIds, retiredComponentIds)
      threat.flowIds = pruneRetired(`威胁 ${threat.code}`, threat.flowIds, retiredFlowIds)
      threat.controlIds = pruneRetired(`威胁 ${threat.code}`, threat.controlIds, retiredControlIds)
      threat.externalDependencyIds = pruneRetired(
        `威胁 ${threat.code}`,
        threat.externalDependencyIds,
        retiredDependencyIds,
      )
    })
  state.controls
    .filter((control) => control.lifecycle !== 'retired')
    .forEach((control) => {
      control.evidenceIds = pruneRetired(`控制 ${control.name}`, control.evidenceIds, retiredEvidenceIds)
    })
  state.mitigations
    .filter((task) => task.lifecycle !== 'retired')
    .forEach((task) => {
      task.evidenceIds = pruneRetired(`缓解任务 ${task.title}`, task.evidenceIds, retiredEvidenceIds)
    })

  return fixes
}

export const readStoredState = (): ThreatModelState | null => {
  const raw = localStorage.getItem(STORAGE_KEY)
  if (!raw) return null
  try {
    return JSON.parse(raw) as ThreatModelState
  } catch {
    return null
  }
}

const writeState = (state: ThreatModelState): void => {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(state))
}

export const loadState = (): ThreatModelState => {
  const stored = readStoredState()
  if (!stored) {
    const seed = createSeedState()
    writeState(seed)
    return seed
  }

  const fixes = migrateState(stored)
  if (fixes.length > 0) {
    stored.audit.unshift({
      id: createId('aud'),
      entityType: 'migration',
      entityId: `schema-v${SCHEMA_VERSION}`,
      action: '数据迁移',
      actor: '系统',
      createdAt: new Date().toISOString(),
      detail: `旧数据首次打开完成迁移：${fixes.join('；')}`,
    })
    writeState(stored)
  }
  return stored
}

export const saveState = (state: ThreatModelState): void => {
  writeState(state)
}

export const resetState = (): ThreatModelState => {
  const seed = createSeedState()
  writeState(seed)
  return seed
}
