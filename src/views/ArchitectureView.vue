<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import Button from 'primevue/button'
import Column from 'primevue/column'
import DataTable from 'primevue/datatable'
import Dialog from 'primevue/dialog'
import InputText from 'primevue/inputtext'
import Select from 'primevue/select'
import Tab from 'primevue/tab'
import TabList from 'primevue/tablist'
import TabPanel from 'primevue/tabpanel'
import TabPanels from 'primevue/tabpanels'
import Tabs from 'primevue/tabs'
import Tag from 'primevue/tag'
import Textarea from 'primevue/textarea'
import { useToast } from 'primevue/usetoast'
import DataFlowDiagram from '@/components/DataFlowDiagram.vue'
import PageHeader from '@/components/PageHeader.vue'
import StatusTag from '@/components/StatusTag.vue'
import type {
  ArchitectureComponent,
  DataFlow,
  ExternalDependency,
  SystemBoundary,
  TrustZone,
} from '@/models/domain'
import {
  buildRemovalPlan,
  REMOVABLE_LABEL,
  type RemovableKind,
} from '@/services/cleanup'
import { createId } from '@/services/repository'
import { activeComponents, activeFlows, isRetired } from '@/services/selectors'
import { useThreatModelStore, type CommitResult } from '@/stores/threatModel'

const store = useThreatModelStore()
const toast = useToast()
const activeTab = ref('components')

const boundaryVisible = ref(false)
const componentVisible = ref(false)
const flowVisible = ref(false)
const dependencyVisible = ref(false)
const showRetired = ref(false)

const boundaryForm = reactive<SystemBoundary>({ ...store.data.boundary })
const componentForm = reactive<ArchitectureComponent>({
  id: '',
  name: '',
  type: 'service',
  zoneId: '',
  criticality: 'medium',
  owner: '',
  description: '',
})
const flowForm = reactive<DataFlow>({
  id: '',
  name: '',
  sourceId: '',
  targetId: '',
  protocol: 'HTTPS',
  dataClass: 'internal',
  crossesTrustBoundary: true,
  description: '',
})
const dependencyForm = reactive<ExternalDependency>({
  id: '',
  name: '',
  vendor: '',
  purpose: '',
  dataClass: 'internal',
  owner: '',
  status: 'active',
})

const componentTypes = [
  { label: '业务服务', value: 'service' },
  { label: '数据资产', value: 'asset' },
  { label: '数据存储', value: 'data_store' },
  { label: '安全网关', value: 'gateway' },
  { label: '客户端', value: 'client' },
]
const criticalities = [
  { label: '严重', value: 'critical' },
  { label: '高', value: 'high' },
  { label: '中', value: 'medium' },
  { label: '低', value: 'low' },
]
const dataClasses = [
  { label: '公开', value: 'public' },
  { label: '内部', value: 'internal' },
  { label: '机密', value: 'confidential' },
  { label: '受限', value: 'restricted' },
]

const activeComponentList = computed(() => activeComponents(store.data))
const activeFlowList = computed(() => activeFlows(store.data))
const visibleComponents = computed(() =>
  showRetired.value ? store.data.components : activeComponentList.value,
)
const visibleFlows = computed(() =>
  showRetired.value ? store.data.flows : activeFlowList.value,
)
const visibleDependencies = computed(() =>
  showRetired.value
    ? store.data.dependencies
    : store.data.dependencies.filter((dependency) => dependency.status !== 'retired'),
)
const retiredCount = computed(
  () =>
    store.data.components.filter(isRetired).length +
    store.data.flows.filter(isRetired).length +
    store.data.dependencies.filter((dependency) => dependency.status === 'retired').length,
)

// —— 移除影响分析：对话框预览与实际执行共用同一份计划 ——
const removalTarget = ref<{ kind: RemovableKind; id: string } | null>(null)
const removalVisible = ref(false)
const removalPlan = computed(() =>
  removalTarget.value
    ? buildRemovalPlan(store.data, removalTarget.value.kind, removalTarget.value.id)
    : null,
)
const removalCascadeAll = computed(() =>
  removalPlan.value ? [...removalPlan.value.cascade, ...removalPlan.value.evidenceCascade] : [],
)

const openRemoval = (kind: RemovableKind, id: string): void => {
  removalTarget.value = { kind, id }
  removalVisible.value = true
}

const confirmRemoval = (): void => {
  if (!removalTarget.value) return
  const result = store.removeArchitectureEntity(removalTarget.value.kind, removalTarget.value.id)
  if (result.conflict) {
    toast.add({
      severity: 'warn',
      summary: '引用关系已变化',
      detail: '其他窗口已更新模型，请按最新引用关系重新确认。',
      life: 4500,
    })
    if (!removalPlan.value) removalVisible.value = false
    return
  }
  removalVisible.value = false
  removalTarget.value = null
  if (!result.ok) {
    toast.add({
      severity: 'error',
      summary: '清理未完成',
      detail: '批量处理中途失败，可在页面顶部恢复未完成项。',
      life: 4500,
    })
    return
  }
  const plan = result.plan
  toast.add({
    severity: 'success',
    summary: plan?.targetDisposition === 'retire' ? '已停用并保留历史' : '已移除',
    detail: plan?.label ?? '',
    life: 4000,
  })
}

const resumeJobs = (): void => {
  const result = store.resumePendingJobs()
  toast.add({
    severity: result.ok ? 'success' : result.conflict ? 'warn' : 'error',
    summary: result.ok ? '清理任务已恢复完成' : result.conflict ? '引用关系已变化' : '恢复中断',
    detail: result.ok
      ? '未完成的清理项已续跑。'
      : result.conflict
        ? '其他窗口已更新模型，请稍后重试。'
        : '仍有任务项失败，请查看审计轨迹。',
    life: 4000,
  })
}

const notifyIfConflict = (result: CommitResult, successSummary: string, detail: string): void => {
  if (result.conflict) {
    toast.add({
      severity: 'warn',
      summary: '引用关系已变化',
      detail: '其他窗口已先提交修改，本地内容已刷新，请确认后重试。',
      life: 4500,
    })
    return
  }
  toast.add({ severity: 'success', summary: successSummary, detail, life: 2500 })
}

const resetComponentForm = (item?: ArchitectureComponent): void => {
  Object.assign(
    componentForm,
    item ?? {
      id: '',
      name: '',
      type: 'service',
      zoneId: store.data.zones[0]?.id ?? '',
      criticality: 'medium',
      owner: '',
      description: '',
    },
  )
  componentVisible.value = true
}

const resetFlowForm = (item?: DataFlow): void => {
  Object.assign(
    flowForm,
    item ?? {
      id: '',
      name: '',
      sourceId: activeComponentList.value[0]?.id ?? '',
      targetId: activeComponentList.value[1]?.id ?? '',
      protocol: 'HTTPS',
      dataClass: 'internal',
      crossesTrustBoundary: true,
      description: '',
    },
  )
  flowVisible.value = true
}

const resetDependencyForm = (item?: ExternalDependency): void => {
  Object.assign(
    dependencyForm,
    item ?? {
      id: '',
      name: '',
      vendor: '',
      purpose: '',
      dataClass: 'internal',
      owner: '',
      status: 'active',
    },
  )
  dependencyVisible.value = true
}

const saveBoundary = (): void => {
  if (!boundaryForm.name.trim() || !boundaryForm.owner.trim()) {
    toast.add({ severity: 'error', summary: '校验失败', detail: '边界名称与负责人不能为空', life: 3000 })
    return
  }
  const result = store.updateBoundary({ ...boundaryForm })
  if (result.ok) boundaryVisible.value = false
  notifyIfConflict(result, '已保存', '系统边界已更新')
}

const saveComponent = (): void => {
  if (!componentForm.name.trim() || !componentForm.zoneId || !componentForm.owner.trim()) {
    toast.add({ severity: 'error', summary: '校验失败', detail: '名称、信任区和负责人不能为空', life: 3000 })
    return
  }
  const component: ArchitectureComponent = {
    ...componentForm,
    id: componentForm.id || createId('cmp'),
    lifecycle: 'active',
  }
  const result = store.saveEntity('components', component)
  if (result.ok) componentVisible.value = false
  notifyIfConflict(result, '组件已保存', componentForm.name)
}

const saveFlow = (): void => {
  if (!flowForm.name.trim() || !flowForm.sourceId || !flowForm.targetId) {
    toast.add({ severity: 'error', summary: '校验失败', detail: '名称、源组件和目标组件不能为空', life: 3000 })
    return
  }
  if (flowForm.sourceId === flowForm.targetId) {
    toast.add({ severity: 'error', summary: '校验失败', detail: '源组件与目标组件不能相同', life: 3000 })
    return
  }
  const flow: DataFlow = {
    ...flowForm,
    id: flowForm.id || createId('flow'),
    lifecycle: 'active',
  }
  const result = store.saveEntity('flows', flow)
  if (result.ok) flowVisible.value = false
  notifyIfConflict(result, '数据流已保存', flowForm.name)
}

const saveDependency = (): void => {
  if (!dependencyForm.name.trim() || !dependencyForm.vendor.trim() || !dependencyForm.owner.trim()) {
    toast.add({ severity: 'error', summary: '校验失败', detail: '依赖、供应商和负责人不能为空', life: 3000 })
    return
  }
  const result = store.saveEntity('dependencies', {
    ...dependencyForm,
    id: dependencyForm.id || createId('dep'),
  })
  if (result.ok) dependencyVisible.value = false
  notifyIfConflict(result, '外部依赖已保存', dependencyForm.name)
}

const componentName = (id: string): string =>
  store.data.components.find((component) => component.id === id)?.name ?? `${id}（已移除）`
const zoneName = (id: string): string =>
  store.data.zones.find((zone) => zone.id === id)?.name ?? id

const saveZone = (zone: TrustZone): void => {
  store.saveEntity('zones', zone)
}
</script>

<template>
  <div class="page">
    <PageHeader
      eyebrow="模型基线"
      title="架构、边界与数据流"
      description="维护系统边界、信任区、资产组件、数据流和外部依赖，作为威胁分析的结构化输入。"
    />

    <section v-if="store.incompleteJobs.length > 0" class="resume-banner">
      <i class="pi pi-replay"></i>
      <div>
        <strong>有 {{ store.incompleteJobs.length }} 个清理任务未完成</strong>
        <span>{{ store.incompleteJobs[0]?.label }}。批量处理中断的剩余项可以现在恢复。</span>
      </div>
      <Button label="恢复未完成项" icon="pi pi-play" size="small" @click="resumeJobs" />
    </section>

    <section class="boundary-strip">
      <div>
        <span>当前系统</span>
        <strong>{{ store.data.boundary.name }}</strong>
      </div>
      <div>
        <span>范围</span>
        <strong>{{ store.data.boundary.inScope }}</strong>
      </div>
      <div>
        <span>排除项</span>
        <strong>{{ store.data.boundary.outOfScope }}</strong>
      </div>
      <Button label="编辑边界" icon="pi pi-pencil" outlined @click="boundaryVisible = true" />
    </section>

    <section class="panel">
      <div class="panel-header">
        <h2 class="panel-title">数据流图</h2>
        <span class="muted">
          {{ activeComponentList.length }} 个组件，{{ activeFlowList.length }} 条流
          <template v-if="retiredCount > 0">（{{ retiredCount }} 项已停用保留历史）</template>
        </span>
      </div>
      <DataFlowDiagram />
    </section>

    <Tabs v-model:value="activeTab">
      <TabList>
        <Tab value="components">组件与资产</Tab>
        <Tab value="zones">信任区</Tab>
        <Tab value="flows">数据流</Tab>
        <Tab value="dependencies">外部依赖</Tab>
      </TabList>
      <TabPanels>
        <TabPanel value="components">
          <div class="tab-toolbar">
            <div>
              <strong>架构组件</strong>
              <span>移除前会展示引用关系：仅被草稿引用的一并整理，被版本或会签使用的转停用。</span>
            </div>
            <div class="toolbar-actions">
              <Button
                v-if="retiredCount > 0"
                :label="showRetired ? '隐藏已停用' : `显示已停用 (${retiredCount})`"
                icon="pi pi-history"
                text
                @click="showRetired = !showRetired"
              />
              <Button label="新增组件" icon="pi pi-plus" @click="resetComponentForm()" />
            </div>
          </div>
          <DataTable :value="visibleComponents" dataKey="id" size="small" stripedRows>
            <Column field="name" header="组件">
              <template #body="{ data }">
                <div class="name-cell">
                  <span :class="{ 'retired-text': isRetired(data) }">{{ data.name }}</span>
                  <Tag v-if="isRetired(data)" value="已停用" severity="secondary" />
                </div>
              </template>
            </Column>
            <Column header="类型" style="width: 120px">
              <template #body="{ data }">
                {{ componentTypes.find((item) => item.value === data.type)?.label }}
              </template>
            </Column>
            <Column header="信任区" style="width: 140px">
              <template #body="{ data }">{{ zoneName(data.zoneId) }}</template>
            </Column>
            <Column header="关键度" style="width: 100px">
              <template #body="{ data }">
                <StatusTag :value="data.criticality" kind="severity" />
              </template>
            </Column>
            <Column field="owner" header="负责人" style="width: 150px" />
            <Column header="操作" style="width: 150px">
              <template #body="{ data }">
                <div class="action-stack">
                  <template v-if="!isRetired(data)">
                    <Button
                      icon="pi pi-pencil"
                      label="编辑"
                      size="small"
                      text
                      @click="resetComponentForm(data)"
                    />
                    <Button
                      icon="pi pi-trash"
                      size="small"
                      severity="danger"
                      text
                      aria-label="移除组件"
                      @click="openRemoval('component', data.id)"
                    />
                  </template>
                  <span v-else class="muted retired-reason">{{ data.retireReason ?? '已停用' }}</span>
                </div>
              </template>
            </Column>
          </DataTable>
        </TabPanel>

        <TabPanel value="zones">
          <div class="tab-toolbar">
            <div>
              <strong>信任区</strong>
              <span>跨区数据流默认提高威胁评审优先级。</span>
            </div>
          </div>
          <div class="zone-grid">
            <article v-for="zone in store.data.zones" :key="zone.id" class="zone-item">
              <div>
                <strong>{{ zone.name }}</strong>
                <span>{{ zone.level }}</span>
              </div>
              <p>{{ zone.description }}</p>
              <code>{{ zone.id }}</code>
              <Button
                label="模拟更新说明"
                size="small"
                text
                @click="saveZone({ ...zone, description: `${zone.description} 已复核。` })"
              />
            </article>
          </div>
        </TabPanel>

        <TabPanel value="flows">
          <div class="tab-toolbar">
            <div>
              <strong>数据流清单</strong>
              <span>记录协议、数据级别与是否跨信任区。</span>
            </div>
            <Button label="新增数据流" icon="pi pi-plus" @click="resetFlowForm()" />
          </div>
          <DataTable :value="visibleFlows" dataKey="id" size="small" stripedRows>
            <Column field="name" header="数据流">
              <template #body="{ data }">
                <div class="name-cell">
                  <span :class="{ 'retired-text': isRetired(data) }">{{ data.name }}</span>
                  <Tag v-if="isRetired(data)" value="已停用" severity="secondary" />
                </div>
              </template>
            </Column>
            <Column header="源 → 目标">
              <template #body="{ data }">
                {{ componentName(data.sourceId) }} → {{ componentName(data.targetId) }}
              </template>
            </Column>
            <Column field="protocol" header="协议" style="width: 130px" />
            <Column header="数据级别" style="width: 110px" />
            <Column header="跨信任区" style="width: 100px">
              <template #body="{ data }">
                <StatusTag :value="data.crossesTrustBoundary ? 'high' : 'low'" />
              </template>
            </Column>
            <Column header="操作" style="width: 150px">
              <template #body="{ data }">
                <template v-if="!isRetired(data)">
                  <Button icon="pi pi-pencil" label="编辑" size="small" text @click="resetFlowForm(data)" />
                  <Button
                    icon="pi pi-trash"
                    size="small"
                    severity="danger"
                    text
                    aria-label="移除数据流"
                    @click="openRemoval('flow', data.id)"
                  />
                </template>
                <span v-else class="muted retired-reason">{{ data.retireReason ?? '已停用' }}</span>
              </template>
            </Column>
          </DataTable>
        </TabPanel>

        <TabPanel value="dependencies">
          <div class="tab-toolbar">
            <div>
              <strong>外部依赖</strong>
              <span>外部服务需登记数据级别、供应商与责任团队。</span>
            </div>
            <Button label="新增依赖" icon="pi pi-plus" @click="resetDependencyForm()" />
          </div>
          <DataTable :value="visibleDependencies" dataKey="id" size="small" stripedRows>
            <Column field="name" header="依赖" />
            <Column field="vendor" header="供应商" />
            <Column field="purpose" header="用途" />
            <Column field="dataClass" header="数据级别" style="width: 110px" />
            <Column field="owner" header="负责人" style="width: 140px" />
            <Column header="状态" style="width: 120px">
              <template #body="{ data }">
                <StatusTag :value="data.status" />
              </template>
            </Column>
            <Column header="操作" style="width: 150px">
              <template #body="{ data }">
                <template v-if="data.status !== 'retired'">
                  <Button
                    icon="pi pi-pencil"
                    label="编辑"
                    size="small"
                    text
                    @click="resetDependencyForm(data)"
                  />
                  <Button
                    icon="pi pi-trash"
                    size="small"
                    severity="danger"
                    text
                    aria-label="移除依赖"
                    @click="openRemoval('dependency', data.id)"
                  />
                </template>
                <span v-else class="muted retired-reason">已退役保留历史</span>
              </template>
            </Column>
          </DataTable>
        </TabPanel>
      </TabPanels>
    </Tabs>

    <Dialog
      v-model:visible="removalVisible"
      header="移除前确认：引用关系影响分析"
      modal
      :style="{ width: '760px' }"
    >
      <div v-if="removalPlan" class="removal-plan">
        <div class="removal-target">
          <div>
            <span class="muted">{{ REMOVABLE_LABEL[removalPlan.kind] }}</span>
            <strong>{{ removalPlan.targetName }}</strong>
          </div>
          <Tag
            :value="removalPlan.targetDisposition === 'retire' ? '转停用保留历史' : '直接移除'"
            :severity="removalPlan.targetDisposition === 'retire' ? 'warn' : 'danger'"
          />
        </div>
        <p class="removal-reason">{{ removalPlan.targetReason }}</p>

        <div class="impact-stats">
          <div><span>受影响威胁</span><strong>{{ removalPlan.threats.length }}</strong></div>
          <div><span>级联控制/数据流</span><strong>{{ removalPlan.cascade.length }}</strong></div>
          <div><span>级联证据</span><strong>{{ removalPlan.evidenceCascade.length }}</strong></div>
          <div><span>级联缓解任务</span><strong>{{ removalPlan.mitigationDeleteCount }}</strong></div>
          <div><span>会签记录</span><strong>{{ removalPlan.decisionCount }}</strong></div>
          <div><span>涉及版本</span><strong>{{ removalPlan.versionLabels.length }}</strong></div>
        </div>

        <section v-if="removalPlan.threats.length > 0" class="impact-section">
          <h3>威胁引用（{{ removalPlan.threats.length }}）</h3>
          <div v-for="threat in removalPlan.threats" :key="threat.threatId" class="impact-row">
            <div>
              <strong>{{ threat.code }} {{ threat.title }}</strong>
              <span>{{ threat.reason }}</span>
            </div>
            <Tag
              :value="
                threat.disposition === 'delete'
                  ? '一并删除'
                  : threat.disposition === 'reopen'
                    ? '回到待重审'
                    : '解除引用'
              "
              :severity="
                threat.disposition === 'delete'
                  ? 'danger'
                  : threat.disposition === 'reopen'
                    ? 'warn'
                    : 'info'
              "
            />
          </div>
        </section>

        <section v-if="removalCascadeAll.length > 0" class="impact-section">
          <h3>级联对象（{{ removalCascadeAll.length }}）</h3>
          <div v-for="entity in removalCascadeAll" :key="entity.id" class="impact-row">
            <div>
              <strong>{{ entity.name }}</strong>
              <span>{{ entity.reason }}</span>
            </div>
            <Tag
              :value="entity.disposition === 'retire' ? '转停用' : '一并删除'"
              :severity="entity.disposition === 'retire' ? 'warn' : 'danger'"
            />
          </div>
        </section>

        <section v-if="removalPlan.versionLabels.length > 0" class="impact-section">
          <h3>冻结版本</h3>
          <p class="muted">
            {{ removalPlan.versionLabels.join('、') }} 已冻结上述对象，停用后历史快照仍可追溯。
          </p>
        </section>

        <p class="removal-note">
          确认后将作为批量任务逐项执行：只被草稿引用的条目一并整理；被版本冻结或会签使用的对象转停用并保留历史；相关会签回到待重审。图谱、风险汇总与报告按同一结果更新。
        </p>
      </div>
      <div v-else class="empty-state">该对象已不存在或已被其他窗口移除。</div>
      <template #footer>
        <Button label="取消" severity="secondary" outlined @click="removalVisible = false" />
        <Button
          v-if="removalPlan"
          :label="removalPlan.targetDisposition === 'retire' ? '确认停用并解除引用' : '确认移除'"
          :icon="removalPlan.targetDisposition === 'retire' ? 'pi pi-pause' : 'pi pi-trash'"
          :severity="removalPlan.targetDisposition === 'retire' ? 'warn' : 'danger'"
          @click="confirmRemoval"
        />
      </template>
    </Dialog>

    <Dialog v-model:visible="boundaryVisible" header="编辑系统边界" modal :style="{ width: '680px' }">
      <div class="editor-form">
        <div class="field">
          <label>系统名称</label>
          <InputText v-model="boundaryForm.name" />
        </div>
        <div class="field">
          <label>责任团队</label>
          <InputText v-model="boundaryForm.owner" />
        </div>
        <div class="field field-wide">
          <label>系统说明</label>
          <Textarea v-model="boundaryForm.description" rows="3" />
        </div>
        <div class="field field-wide">
          <label>建模范围内</label>
          <Textarea v-model="boundaryForm.inScope" rows="3" />
        </div>
        <div class="field field-wide">
          <label>明确排除</label>
          <Textarea v-model="boundaryForm.outOfScope" rows="3" />
        </div>
      </div>
      <template #footer>
        <Button label="取消" severity="secondary" outlined @click="boundaryVisible = false" />
        <Button label="保存边界" icon="pi pi-check" @click="saveBoundary" />
      </template>
    </Dialog>

    <Dialog
      v-model:visible="componentVisible"
      :header="componentForm.id ? '编辑组件' : '新增组件'"
      modal
      :style="{ width: '680px' }"
    >
      <div class="editor-form">
        <div class="field">
          <label>组件名称</label>
          <InputText v-model="componentForm.name" />
        </div>
        <div class="field">
          <label>组件类型</label>
          <Select v-model="componentForm.type" :options="componentTypes" option-label="label" option-value="value" />
        </div>
        <div class="field">
          <label>信任区</label>
          <Select
            v-model="componentForm.zoneId"
            :options="store.data.zones"
            option-label="name"
            option-value="id"
          />
        </div>
        <div class="field">
          <label>关键度</label>
          <Select
            v-model="componentForm.criticality"
            :options="criticalities"
            option-label="label"
            option-value="value"
          />
        </div>
        <div class="field">
          <label>负责人</label>
          <InputText v-model="componentForm.owner" />
        </div>
        <div class="field field-wide">
          <label>说明</label>
          <Textarea v-model="componentForm.description" rows="3" />
        </div>
      </div>
      <template #footer>
        <Button label="取消" severity="secondary" outlined @click="componentVisible = false" />
        <Button label="保存组件" icon="pi pi-check" @click="saveComponent" />
      </template>
    </Dialog>

    <Dialog
      v-model:visible="flowVisible"
      :header="flowForm.id ? '编辑数据流' : '新增数据流'"
      modal
      :style="{ width: '720px' }"
    >
      <div class="editor-form">
        <div class="field field-wide">
          <label>数据流名称</label>
          <InputText v-model="flowForm.name" />
        </div>
        <div class="field">
          <label>源组件</label>
          <Select
            v-model="flowForm.sourceId"
            :options="activeComponentList"
            option-label="name"
            option-value="id"
          />
        </div>
        <div class="field">
          <label>目标组件</label>
          <Select
            v-model="flowForm.targetId"
            :options="activeComponentList"
            option-label="name"
            option-value="id"
          />
        </div>
        <div class="field">
          <label>协议</label>
          <InputText v-model="flowForm.protocol" />
        </div>
        <div class="field">
          <label>数据级别</label>
          <Select
            v-model="flowForm.dataClass"
            :options="dataClasses"
            option-label="label"
            option-value="value"
          />
        </div>
        <div class="field field-wide">
          <label>说明</label>
          <Textarea v-model="flowForm.description" rows="3" />
        </div>
      </div>
      <template #footer>
        <Button label="取消" severity="secondary" outlined @click="flowVisible = false" />
        <Button label="保存数据流" icon="pi pi-check" @click="saveFlow" />
      </template>
    </Dialog>

    <Dialog
      v-model:visible="dependencyVisible"
      :header="dependencyForm.id ? '编辑依赖' : '新增依赖'"
      modal
      :style="{ width: '680px' }"
    >
      <div class="editor-form">
        <div class="field">
          <label>依赖名称</label>
          <InputText v-model="dependencyForm.name" />
        </div>
        <div class="field">
          <label>供应商</label>
          <InputText v-model="dependencyForm.vendor" />
        </div>
        <div class="field">
          <label>数据级别</label>
          <Select
            v-model="dependencyForm.dataClass"
            :options="dataClasses"
            option-label="label"
            option-value="value"
          />
        </div>
        <div class="field">
          <label>负责人</label>
          <InputText v-model="dependencyForm.owner" />
        </div>
        <div class="field field-wide">
          <label>用途</label>
          <Textarea v-model="dependencyForm.purpose" rows="3" />
        </div>
      </div>
      <template #footer>
        <Button label="取消" severity="secondary" outlined @click="dependencyVisible = false" />
        <Button label="保存依赖" icon="pi pi-check" @click="saveDependency" />
      </template>
    </Dialog>
  </div>
</template>

<style scoped>
.boundary-strip {
  display: grid;
  grid-template-columns: 0.8fr 1.2fr 1.2fr auto;
  align-items: center;
  gap: 18px;
  padding: 16px;
  border: 1px solid #dce2ea;
  border-left: 4px solid #426f9e;
  border-radius: 6px;
  background: #fff;
}

.boundary-strip > div {
  display: grid;
  gap: 6px;
  min-width: 0;
}

.boundary-strip span {
  color: #727d90;
  font-size: 11px;
}

.boundary-strip strong {
  color: #273247;
  font-size: 13px;
  line-height: 1.45;
}

.resume-banner {
  display: flex;
  align-items: center;
  gap: 13px;
  padding: 13px 16px;
  border: 1px solid #f2c78f;
  border-left: 4px solid #d97706;
  border-radius: 6px;
  background: #fffaf0;
}

.resume-banner > i {
  color: #b45309;
}

.resume-banner > div {
  display: grid;
  gap: 4px;
  flex: 1;
}

.resume-banner span {
  color: #7b5d2c;
  font-size: 12px;
}

.tab-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 16px 0;
}

.tab-toolbar > div {
  display: grid;
  gap: 5px;
}

.tab-toolbar span {
  color: #707b8e;
  font-size: 12px;
}

.toolbar-actions {
  display: flex;
  align-items: center;
  gap: 8px;
}

.name-cell {
  display: flex;
  align-items: center;
  gap: 8px;
}

.retired-text {
  color: #8a94a6;
  text-decoration: line-through;
}

.retired-reason {
  font-size: 11px;
}

.zone-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
  padding-bottom: 16px;
}

.zone-item {
  display: flex;
  flex-direction: column;
  gap: 11px;
  min-height: 172px;
  padding: 15px;
  border: 1px solid #dfe4eb;
  border-radius: 6px;
  background: #fff;
}

.zone-item > div {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.zone-item > div span {
  color: #667189;
  font-size: 11px;
  text-transform: uppercase;
}

.zone-item p {
  flex: 1;
  margin: 0;
  color: #5f6b80;
  font-size: 12px;
  line-height: 1.55;
}

.zone-item code {
  color: #8791a3;
  font-size: 11px;
}

.zone-item :deep(.p-button) {
  align-self: flex-start;
  padding-left: 0;
}

.removal-plan {
  display: grid;
  gap: 16px;
}

.removal-target {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 14px;
  padding: 12px 14px;
  border: 1px solid #e2e6ec;
  border-radius: 6px;
  background: #f8f9fb;
}

.removal-target > div {
  display: grid;
  gap: 4px;
}

.removal-reason {
  margin: 0;
  color: #5b6678;
  font-size: 12px;
}

.impact-stats {
  display: grid;
  grid-template-columns: repeat(6, minmax(0, 1fr));
  gap: 1px;
  overflow: hidden;
  border: 1px solid #e2e6ec;
  border-radius: 6px;
  background: #e2e6ec;
}

.impact-stats > div {
  display: grid;
  gap: 6px;
  padding: 10px;
  background: #fff;
  text-align: center;
}

.impact-stats span {
  color: #6d788c;
  font-size: 10px;
}

.impact-stats strong {
  font-size: 18px;
}

.impact-section h3 {
  margin: 0 0 8px;
  font-size: 13px;
}

.impact-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 8px 10px;
  border: 1px solid #e8ebf0;
  border-radius: 5px;
}

.impact-row + .impact-row {
  margin-top: 6px;
}

.impact-row > div {
  display: grid;
  gap: 3px;
  min-width: 0;
}

.impact-row strong {
  font-size: 12px;
}

.impact-row span {
  color: #727d90;
  font-size: 11px;
}

.removal-note {
  margin: 0;
  padding: 10px 12px;
  border-left: 3px solid #426f9e;
  border-radius: 4px;
  color: #4f5b70;
  background: #f4f7fb;
  font-size: 12px;
  line-height: 1.6;
}
</style>
