import type { ThreatModelState } from '@/models/domain'
import { createSeedState } from '@/models/seed'
import { migrateState, needsMigration } from '@/services/migration'

const STORAGE_KEY = 'scapex-threat-model-v1'

const clone = <T>(value: T): T => structuredClone(value)

const newDataVersion = (): string =>
  `dv-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`

export class ConcurrentUpdateError extends Error {
  constructor(public readonly currentVersion: string) {
    super('引用关系已被另一个窗口改变，请刷新核对后重试')
    this.name = 'ConcurrentUpdateError'
  }
}

export const loadState = (): ThreatModelState => {
  const raw = localStorage.getItem(STORAGE_KEY)
  if (!raw) {
    const seed = createSeedState()
    localStorage.setItem(STORAGE_KEY, JSON.stringify(seed))
    return seed
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    const seed = createSeedState()
    localStorage.setItem(STORAGE_KEY, JSON.stringify(seed))
    return seed
  }

  // 旧数据首次打开：迁移悬空引用与停用标记后落库
  if (needsMigration(parsed)) {
    const migrated = migrateState(parsed)
    localStorage.setItem(STORAGE_KEY, JSON.stringify(migrated))
    return migrated
  }

  return parsed as ThreatModelState
}

/**
 * 带乐观锁的提交。两个窗口同时移除/重建同一编号时：
 * 后一方持有的 expectedVersion 与库中不一致，提交被拒绝并需重新核对引用。
 */
export const commitState = (
  state: ThreatModelState,
  expectedVersion: string,
): { version: string } => {
  const current = loadState()
  if (current.dataVersion !== expectedVersion) {
    throw new ConcurrentUpdateError(current.dataVersion)
  }
  const version = newDataVersion()
  state.dataVersion = version
  localStorage.setItem(STORAGE_KEY, JSON.stringify(clone(state)))
  return { version }
}

export const saveState = (state: ThreatModelState): void => {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(clone(state)))
}

export const resetState = (): ThreatModelState => {
  const seed = createSeedState()
  saveState(seed)
  return seed
}

export const createId = (prefix: string): string =>
  `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`
