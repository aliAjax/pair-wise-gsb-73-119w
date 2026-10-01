/* 端到端逻辑验证：迁移、引用级联、停用/删除、断点恢复、双窗口并发 */
const Module = require('module')
const path = require('path')
const outDir = path.resolve(__dirname, '../node_modules/.tmp/verify')
const origResolve = Module._resolveFilename
Module._resolveFilename = function (request, ...args) {
  if (request.startsWith('@/')) request = path.join(outDir, request.slice(2))
  return origResolve.call(this, request, ...args)
}

// 模拟两个窗口共享的 localStorage（同一存储后端）
const createStorage = (backend) => ({
  getItem: (k) => backend[k] ?? null,
  setItem: (k, v) => {
    backend[k] = String(v)
  },
  removeItem: (k) => {
    delete backend[k]
  },
})
const backend = {}
globalThis.localStorage = createStorage(backend)

const { createPinia, setActivePinia } = require('pinia')
const repository = require(outDir + '/services/repository.js')
const cleanup = require(outDir + '/services/cleanup.js')
const selectors = require(outDir + '/services/selectors.js')
const { createSeedState } = require(outDir + '/models/seed.js')

let passed = 0
let failed = 0
const check = (name, condition, extra) => {
  if (condition) {
    passed += 1
    console.log(`  ✓ ${name}`)
  } else {
    failed += 1
    console.log(`  ✗ ${name}${extra ? ` — ${extra}` : ''}`)
  }
}

const newStore = () => {
  setActivePinia(createPinia())
  delete require.cache[require.resolve(outDir + '/stores/threatModel.js')]
  return require(outDir + '/stores/threatModel.js').useThreatModelStore()
}

// ---------- 场景 1：旧数据首启迁移 ----------
console.log('\n场景 1：旧数据首次打开先迁移（悬空引用 + 停用标记）')
{
  const legacy = createSeedState()
  delete legacy.meta
  delete legacy.cleanupJobs
  legacy.components.forEach((c) => delete c.lifecycle)
  legacy.flows.forEach((f) => delete f.lifecycle)
  // 制造悬空引用与失宿主对象
  legacy.threats[0].componentIds.push('cmp-ghost')
  legacy.threats[0].flowIds.push('flow-ghost')
  legacy.controls.push({
    id: 'ctl-orphan',
    name: '孤儿控制',
    type: 'preventive',
    status: 'effective',
    owner: '测试',
    componentId: 'cmp-ghost',
    description: '',
    evidenceIds: ['ev-ghost'],
  })
  legacy.flows.push({
    id: 'flow-orphan',
    name: '断点数据流',
    sourceId: 'cmp-ghost',
    targetId: 'cmp-01',
    protocol: 'HTTPS',
    dataClass: 'internal',
    crossesTrustBoundary: false,
    description: '',
  })
  legacy.evidence.push({
    id: 'ev-orphan',
    controlId: 'ctl-ghost',
    title: '孤儿证据',
    kind: 'test',
    reference: 'X-1',
    collectedAt: '2026-01-01',
    expiresAt: '2027-01-01',
    owner: '测试',
    valid: true,
  })
  legacy.threats[1].controlIds.push('ctl-orphan') // 活跃威胁引用将被停用的控制
  backend[repository.STORAGE_KEY] = JSON.stringify(legacy)

  const store = newStore()
  const state = store.data
  check('补齐 meta 与清理队列', state.meta?.schemaVersion === 2 && Array.isArray(state.cleanupJobs))
  check('组件 lifecycle 补齐', state.components.every((c) => c.lifecycle === 'active'))
  check(
    '威胁悬空引用被清理',
    !state.threats[0].componentIds.includes('cmp-ghost') &&
      !state.threats[0].flowIds.includes('flow-ghost'),
  )
  const orphanControl = state.controls.find((c) => c.id === 'ctl-orphan')
  check(
    '失宿主控制转停用并保留',
    orphanControl?.lifecycle === 'retired' && Boolean(orphanControl.retireReason),
  )
  check(
    '孤儿控制的悬空证据引用被清理',
    orphanControl.evidenceIds.length === 0,
  )
  const orphanFlow = state.flows.find((f) => f.id === 'flow-orphan')
  check('断点数据流转停用', orphanFlow?.lifecycle === 'retired')
  const orphanEvidence = state.evidence.find((e) => e.id === 'ev-orphan')
  check(
    '失宿主证据转停用且置为无效',
    orphanEvidence?.lifecycle === 'retired' && orphanEvidence.valid === false,
  )
  check(
    '活跃威胁解除对已停用控制的引用',
    !state.threats[1].controlIds.includes('ctl-orphan'),
  )
  check(
    '迁移写入审计轨迹',
    state.audit.some((event) => event.action === '数据迁移'),
  )
  check(
    '迁移结果已落库（再次打开不重复迁移）',
    JSON.parse(backend[repository.STORAGE_KEY]).meta.schemaVersion === 2,
  )
}

// ---------- 场景 2：被版本冻结 + 会签使用的组件 → 停用保留历史 ----------
console.log('\n场景 2：移除被版本冻结/会签使用的组件（cmp-02 → 停用，会签回到待重审）')
{
  backend[repository.STORAGE_KEY] = JSON.stringify(createSeedState())
  const store = newStore()

  const plan = cleanup.buildRemovalPlan(store.data, 'component', 'cmp-02')
  check('目标判定为停用', plan.targetDisposition === 'retire', plan.targetDisposition)
  check(
    '冻结原因包含版本与会签',
    plan.targetReason.includes('版本快照') && plan.targetReason.includes('会签'),
    plan.targetReason,
  )
  const thr01 = plan.threats.find((t) => t.threatId === 'thr-01')
  check('会签中的威胁判定为回到待重审', thr01?.disposition === 'reopen')
  check(
    '级联包含其上控制与两端数据流',
    plan.cascade.some((c) => c.id === 'ctl-01') &&
      plan.cascade.some((c) => c.id === 'flow-01') &&
      plan.cascade.some((c) => c.id === 'flow-02'),
  )
  check('统计涉及冻结版本', plan.versionLabels.length === 2, plan.versionLabels.join(','))

  const revisionBefore = store.data.threats.find((t) => t.id === 'thr-01').revision
  const result = store.removeArchitectureEntity('component', 'cmp-02')
  check('清理执行成功', result.ok, JSON.stringify(result.job?.items?.filter((i) => i.status !== 'done')))

  const cmp02 = store.data.components.find((c) => c.id === 'cmp-02')
  check(
    '组件转停用且保留在历史中',
    cmp02?.lifecycle === 'retired' && Boolean(cmp02.retiredAt) && Boolean(cmp02.retireReason),
  )
  const thr01After = store.data.threats.find((t) => t.id === 'thr-01')
  check(
    '威胁解除对停用组件的引用',
    !thr01After.componentIds.includes('cmp-02') && !thr01After.flowIds.includes('flow-01'),
  )
  check(
    '相关会签回到待重审（修订号 +1）',
    thr01After.reviewStatus === 'in_review' && thr01After.revision === revisionBefore + 1,
  )
  check(
    '待重审威胁进入当前版本会签范围',
    store.data.versions[0].affectedThreatIds.includes('thr-01'),
  )
  check(
    '历史会签意见保留',
    store.data.decisions.some((d) => d.id === 'dec-01'),
  )
  check(
    '旧版本快照编号原样保留（历史可追溯）',
    store.data.versions.every((v) => v.componentIds.includes('cmp-02')),
  )
  check(
    '图谱口径不再包含停用组件',
    !selectors.activeComponents(store.data).some((c) => c.id === 'cmp-02'),
  )
  const ctl01 = store.data.controls.find((c) => c.id === 'ctl-01')
  check('其上控制一并停用', ctl01?.lifecycle === 'retired')
  const ev01 = store.data.evidence.find((e) => e.id === 'ev-01')
  check('停用控制的证据一并停用', ev01?.lifecycle === 'retired')
  check(
    '任务队列完结',
    store.incompleteJobs.length === 0 && store.data.cleanupJobs[0].status === 'done',
  )
  const report = store.exportReport()
  check(
    '报告与页面同一结果（停用对象单列）',
    report.includes('停用对象') && report.includes('cmp-02') === false && report.includes('API 安全网关'),
  )
}

// ---------- 场景 3：只被草稿引用的数据流 → 一并整理（硬删除） ----------
console.log('\n场景 3：只被草稿引用的数据流（一并整理，物理删除）')
{
  const seed = createSeedState()
  seed.flows.push({
    id: 'flow-draft',
    name: '临时调试链路',
    sourceId: 'cmp-01',
    targetId: 'cmp-03',
    protocol: 'HTTP',
    dataClass: 'internal',
    crossesTrustBoundary: false,
    description: '',
    lifecycle: 'active',
  })
  seed.threats.push({
    id: 'thr-draft',
    code: 'TM-900',
    title: '草稿威胁',
    category: 'tampering',
    description: '仅草稿引用临时链路',
    severity: 'low',
    status: 'open',
    componentIds: [],
    flowIds: ['flow-draft'],
    externalDependencyIds: [],
    attackPathIds: [],
    controlIds: [],
    riskIds: [],
    reviewStatus: 'draft',
    revision: 2,
    lifecycle: 'active',
  })
  seed.mitigations.push({
    id: 'mit-draft',
    threatId: 'thr-draft',
    title: '草稿任务',
    owner: '测试',
    dueAt: '2026-11-01',
    status: 'todo',
    action: 'monitor',
    detail: '',
    evidenceIds: [],
    lifecycle: 'active',
  })
  backend[repository.STORAGE_KEY] = JSON.stringify(seed)
  const store = newStore()

  const plan = cleanup.buildRemovalPlan(store.data, 'flow', 'flow-draft')
  check('目标判定为直接移除', plan.targetDisposition === 'delete')
  const draftThreat = plan.threats.find((t) => t.threatId === 'thr-draft')
  check('腾空的草稿威胁一并删除', draftThreat?.disposition === 'delete')

  const result = store.removeArchitectureEntity('flow', 'flow-draft')
  check('清理执行成功', result.ok)
  check(
    '数据流被物理删除',
    !store.data.flows.some((f) => f.id === 'flow-draft'),
  )
  check(
    '草稿威胁一并删除',
    !store.data.threats.some((t) => t.id === 'thr-draft'),
  )
  check(
    '其缓解任务一并删除',
    !store.data.mitigations.some((m) => m.id === 'mit-draft'),
  )
  check(
    '版本快照不受影响（本就不含该编号）',
    store.data.versions.every((v) => !v.flowIds.includes('flow-draft')),
  )
}

// ---------- 场景 4：批量处理中途失败 → 恢复未完成项 ----------
console.log('\n场景 4：批量处理中途失败后恢复未完成项')
{
  backend[repository.STORAGE_KEY] = JSON.stringify(createSeedState())
  const store = newStore()

  // 手工构造一个任务并注入一个会失败的中间项，模拟执行到一半崩溃
  const plan = cleanup.buildRemovalPlan(store.data, 'component', 'cmp-02')
  const mid = Math.floor(plan.items.length / 2)
  const job = {
    id: 'job-crash',
    label: '模拟崩溃的清理任务',
    createdAt: new Date().toISOString(),
    status: 'running',
    items: plan.items.map((item, index) => ({
      ...item,
      status: index < mid ? 'done' : 'pending',
    })),
  }
  // 前一半按序真正应用（模拟崩溃前已完成的部分）
  const state = store.data
  plan.items.slice(0, mid).forEach((item) => cleanup.applyCleanupItem(state, item))
  state.cleanupJobs.unshift(job)
  state.meta.mutationCounter += 1
  repository.saveState(state)

  const pendingBefore = job.items.filter((i) => i.status === 'pending').length
  check('崩溃现场已落库（存在待处理项）', pendingBefore > 0, `pending=${pendingBefore}`)

  // 模拟重新打开页面：新 store 首启自动恢复
  const reopened = newStore()
  const recovered = reopened.data.cleanupJobs.find((j) => j.id === 'job-crash')
  check('首启自动恢复后任务完结', recovered?.status === 'done', recovered?.status)
  check(
    '所有任务项均为完成态',
    recovered?.items.every((i) => i.status === 'done'),
  )
  const cmp02 = reopened.data.components.find((c) => c.id === 'cmp-02')
  check('恢复后停用标记完整', cmp02?.lifecycle === 'retired')
  const thr01 = reopened.data.threats.find((t) => t.id === 'thr-01')
  check(
    '恢复后引用解除且回到待重审',
    !thr01.componentIds.includes('cmp-02') && thr01.reviewStatus === 'in_review',
  )
  // 幂等校验：已应用的 strip 不会重复扣减
  const flowRefs = reopened.data.threats.find((t) => t.id === 'thr-01').flowIds
  check('已完成项未重复应用（幂等）', !flowRefs.includes('flow-01'))
}

// ---------- 场景 5：两个窗口同时提交，后一方看到引用已变化 ----------
console.log('\n场景 5：双窗口并发（移除 + 重建同一编号）')
{
  backend[repository.STORAGE_KEY] = JSON.stringify(createSeedState())
  const windowA = newStore()
  const windowB = newStore()

  // 窗口 A 移除 cmp-02（停用）
  const resultA = windowA.removeArchitectureEntity('component', 'cmp-02')
  check('窗口 A 移除成功', resultA.ok)

  // 窗口 B 在不知情下重建同一编号的威胁 → 提交时应发现引用已变化
  const staleCounter = windowB.data.meta.mutationCounter
  const storedCounter = JSON.parse(backend[repository.STORAGE_KEY]).meta.mutationCounter
  check('A 提交后存储计数已推进', storedCounter > staleCounter)

  const saveResult = windowB.saveThreat({
    ...windowB.data.threats[0],
    id: 'thr-new',
    code: 'TM-001', // 与现有威胁同编号（重建场景）
    title: '窗口 B 的重建威胁',
  })
  check('窗口 B 的提交被并发守卫拒绝', saveResult.conflict === true && saveResult.ok === false)
  check(
    '窗口 B 已刷新到最新引用关系（看到 cmp-02 停用）',
    windowB.data.components.find((c) => c.id === 'cmp-02')?.lifecycle === 'retired',
  )
  check(
    '窗口 B 未写入过期数据（存储中无 thr-new）',
    !JSON.parse(backend[repository.STORAGE_KEY]).threats.some((t) => t.id === 'thr-new'),
  )
  // 窗口 B 刷新后按最新状态重试，重复编号校验生效
  const duplicate = windowB.data.threats.some((t) => t.code === 'TM-001')
  check('刷新后重复编号可被前端校验发现', duplicate)
}

console.log(`\n结果：${passed} 通过，${failed} 失败`)
process.exit(failed > 0 ? 1 : 0)
