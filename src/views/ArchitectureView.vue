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
import { createId } from '@/services/repository'
import type { CleanupTargetKind, RemovalPlan } from '@/services/lifecycle'
import { isActive } from '@/services/selectors'
import { PlanConflictError, useThreatModelStore } from '@/stores/threatModel'

const store = useThreatModelStore()
const toast = useToast()
const activeTab = ref('components')

const boundaryVisible = ref(false)
const componentVisible = ref(false)
const flowVisible = ref(false)
const dependencyVisible = ref(false)
const cleanupVisible = ref(false)
const cleanupSubmitting = ref(false)

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

// ---- 删前引用核对 ----
const cleanupTargets = ref<{ kind: CleanupTargetKind; id: string }[]>([])
const cleanupPlan = ref<RemovalPlan | null>(null)
const cleanupBatch = ref(false)

const openCleanup = (kind: CleanupTargetKind, id: string): void => {
  cleanupBatch.value = false
  cleanupTargets.value = [{ kind, id }]
  cleanupPlan.value = store.planCleanup(cleanupTargets.value)
  cleanupVisible.value = true
}

const selectedComponents = ref<ArchitectureComponent[]>([])
const selectedFlows = ref<DataFlow[]>([])
const selectedDependencies = ref<ExternalDependency[]>([])

const openBatchCleanup = (kind: CleanupTargetKind): void => {
  const ids =
    kind === 'component'
      ? selectedComponents.value.map((item) => item.id)
      : kind === 'flow'
        ? selectedFlows.value.map((item) => item.id)
        : selectedDependencies.value.map((item) => item.id)
  if (ids.length === 0) {
    toast.add({ severity: 'warn', summary: '未选择条目', detail: '请先勾选需要整理的编号', life: 2500 })
    return
  }
  cleanupBatch.value = true
  cleanupTargets.value = ids.map((id) => ({ kind, id }))
  cleanupPlan.value = store.planCleanup(cleanupTargets.value)
  cleanupVisible.value = true
}

const confirmCleanup = (): void => {
  if (!cleanupPlan.value) return
  cleanupSubmitting.value = true
  try {
    if (cleanupBatch.value) {
      store.startBatchCleanup(
        cleanupTargets.value[0]?.kind ?? 'component',
        cleanupTargets.value.map((target) => target.id),
      )
      toast.add({
        severity: 'success',
        summary: '批量处理已开始',
        detail: '逐项提交，中断后可在页面顶部恢复未完成项',
        life: 3000,
      })
    } else {
      store.submitCleanup(cleanupPlan.value)
      toast.add({ severity: 'success', summary: '清理完成', detail: '图谱、风险汇总与报告已同步更新', life: 3000 })
    }
    cleanupVisible.value = false
    selectedComponents.value = []
    selectedFlows.value = []
    selectedDependencies.value = []
  } catch (error) {
    if (error instanceof PlanConflictError) {
      // 引用已被另一窗口改变：重建计划让后一方看到最新引用
      cleanupPlan.value = store.planCleanup(cleanupTargets.value)
      toast.add({
        severity: 'error',
        summary: '引用关系已变化',
        detail: '另一窗口已经提交，请核对下方最新结果后重试',
        life: 4000,
      })
    } else {
      toast.add({
        severity: 'error',
        summary: '提交被拒绝',
        detail: error instanceof Error ? error.message : '未知错误',
        life: 4000,
      })
      cleanupPlan.value = store.planCleanup(cleanupTargets.value)
    }
  } finally {
    cleanupSubmitting.value = false
  }
}

const resumeJob = (jobId: string): void => {
  store.resumeCleanupJob(jobId)
  toast.add({ severity: 'success', summary: '已恢复处理', detail: '继续提交未完成的编号', life: 2500 })
}

const dismissJob = (jobId: string): void => {
  store.dismissCleanupJob(jobId)
}

const planDeactivateItems = computed(() => cleanupPlan.value?.items.filter((item) => item.mode === 'deactivate') ?? [])
const planDeleteItems = computed(() => cleanupPlan.value?.items.filter((item) => item.mode === 'delete') ?? [])

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
      sourceId: store.data.components[0]?.id ?? '',
      targetId: store.data.components[1]?.id ?? '',
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
  store.updateBoundary({ ...boundaryForm })
  boundaryVisible.value = false
  toast.add({ severity: 'success', summary: '已保存', detail: '系统边界已更新', life: 2500 })
}

const saveComponent = (): void => {
  if (!componentForm.name.trim() || !componentForm.zoneId || !componentForm.owner.trim()) {
    toast.add({ severity: 'error', summary: '校验失败', detail: '名称、信任区和负责人不能为空', life: 3000 })
    return
  }
  store.saveEntity('components', {
    ...componentForm,
    id: componentForm.id || createId('cmp'),
  })
  componentVisible.value = false
  toast.add({ severity: 'success', summary: '组件已保存', detail: componentForm.name, life: 2500 })
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
  store.saveEntity('flows', { ...flowForm, id: flowForm.id || createId('flow') })
  flowVisible.value = false
  toast.add({ severity: 'success', summary: '数据流已保存', detail: flowForm.name, life: 2500 })
}

const saveDependency = (): void => {
  if (!dependencyForm.name.trim() || !dependencyForm.vendor.trim() || !dependencyForm.owner.trim()) {
    toast.add({ severity: 'error', summary: '校验失败', detail: '依赖、供应商和负责人不能为空', life: 3000 })
    return
  }
  store.saveEntity('dependencies', {
    ...dependencyForm,
    id: dependencyForm.id || createId('dep'),
  })
  dependencyVisible.value = false
  toast.add({ severity: 'success', summary: '外部依赖已保存', detail: dependencyForm.name, life: 2500 })
}

const componentName = (id: string): string =>
  store.data.components.find((component) => component.id === id)?.name ?? id
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

    <section v-if="store.interruptedJobs.length > 0" class="resume-banner">
      <i class="pi pi-history"></i>
      <div class="resume-copy">
        <strong>批量清理存在未完成项</strong>
        <span v-for="job in store.interruptedJobs" :key="job.id" class="resume-row">
          任务 {{ job.id.slice(-6) }}：{{ job.failedSignatures.length
          }} 项待恢复（{{ job.lastError }}）
          <Button label="继续处理" size="small" @click="resumeJob(job.id)" />
          <Button label="关闭任务" size="small" severity="secondary" text @click="dismissJob(job.id)" />
        </span>
      </div>
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
          {{ store.data.components.filter((item) => isActive(item.lifecycle)).length }} 个活动组件，{{
            store.data.flows.filter((item) => isActive(item.lifecycle)).length
          }}
          条活动流
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
              <span>组件必须进入威胁分析范围，或明确记录豁免；删除前会先核对引用关系。</span>
            </div>
            <div class="toolbar-actions">
              <Button
                label="批量清理选中"
                icon="pi pi-trash"
                severity="danger"
                outlined
                :disabled="selectedComponents.length === 0"
                @click="openBatchCleanup('component')"
              />
              <Button label="新增组件" icon="pi pi-plus" @click="resetComponentForm()" />
            </div>
          </div>
          <DataTable
            v-model:selection="selectedComponents"
            :value="store.data.components"
            dataKey="id"
            size="small"
            stripedRows
          >
            <Column selectionMode="multiple" headerStyle="width: 3rem" />
            <Column header="组件">
              <template #body="{ data }">
                <div class="name-cell">
                  <strong>{{ data.name }}</strong>
                  <Tag v-if="!isActive(data.lifecycle)" value="已停用" severity="secondary" />
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
            <Column header="操作" style="width: 180px">
              <template #body="{ data }">
                <div class="action-stack">
                  <Button
                    icon="pi pi-pencil"
                    label="编辑"
                    size="small"
                    text
                    :disabled="!isActive(data.lifecycle)"
                    @click="resetComponentForm(data)"
                  />
                  <Button
                    icon="pi pi-trash"
                    label="清理"
                    size="small"
                    severity="danger"
                    text
                    :aria-label="`清理组件 ${data.name}`"
                    @click="openCleanup('component', data.id)"
                  />
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
              <span>记录协议、数据级别与是否跨信任区；清理会同时核对端点与关联威胁。</span>
            </div>
            <div class="toolbar-actions">
              <Button
                label="批量清理选中"
                icon="pi pi-trash"
                severity="danger"
                outlined
                :disabled="selectedFlows.length === 0"
                @click="openBatchCleanup('flow')"
              />
              <Button label="新增数据流" icon="pi pi-plus" @click="resetFlowForm()" />
            </div>
          </div>
          <DataTable
            v-model:selection="selectedFlows"
            :value="store.data.flows"
            dataKey="id"
            size="small"
            stripedRows
          >
            <Column selectionMode="multiple" headerStyle="width: 3rem" />
            <Column header="数据流">
              <template #body="{ data }">
                <div class="name-cell">
                  <strong>{{ data.name }}</strong>
                  <Tag v-if="!isActive(data.lifecycle)" value="已停用" severity="secondary" />
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
            <Column header="操作" style="width: 180px">
              <template #body="{ data }">
                <Button
                  icon="pi pi-pencil"
                  label="编辑"
                  size="small"
                  text
                  :disabled="!isActive(data.lifecycle)"
                  @click="resetFlowForm(data)"
                />
                <Button
                  icon="pi pi-trash"
                  label="清理"
                  size="small"
                  severity="danger"
                  text
                  aria-label="清理数据流"
                  @click="openCleanup('flow', data.id)"
                />
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
            <div class="toolbar-actions">
              <Button
                label="批量清理选中"
                icon="pi pi-trash"
                severity="danger"
                outlined
                :disabled="selectedDependencies.length === 0"
                @click="openBatchCleanup('dependency')"
              />
              <Button label="新增依赖" icon="pi pi-plus" @click="resetDependencyForm()" />
            </div>
          </div>
          <DataTable
            v-model:selection="selectedDependencies"
            :value="store.data.dependencies"
            dataKey="id"
            size="small"
            stripedRows
          >
            <Column selectionMode="multiple" headerStyle="width: 3rem" />
            <Column header="依赖">
              <template #body="{ data }">
                <div class="name-cell">
                  <strong>{{ data.name }}</strong>
                  <Tag v-if="!isActive(data.lifecycle)" value="已停用" severity="secondary" />
                </div>
              </template>
            </Column>
            <Column field="vendor" header="供应商" />
            <Column field="purpose" header="用途" />
            <Column field="dataClass" header="数据级别" style="width: 110px" />
            <Column field="owner" header="负责人" style="width: 140px" />
            <Column header="状态" style="width: 120px">
              <template #body="{ data }">
                <StatusTag :value="data.status" />
              </template>
            </Column>
            <Column header="操作" style="width: 180px">
              <template #body="{ data }">
                <Button
                  icon="pi pi-pencil"
                  label="编辑"
                  size="small"
                  text
                  :disabled="!isActive(data.lifecycle)"
                  @click="resetDependencyForm(data)"
                />
                <Button
                  icon="pi pi-trash"
                  label="清理"
                  size="small"
                  severity="danger"
                  text
                  aria-label="清理外部依赖"
                  @click="openCleanup('dependency', data.id)"
                />
              </template>
            </Column>
          </DataTable>
        </TabPanel>
      </TabPanels>
    </Tabs>

    <!-- 删前引用核对 -->
    <Dialog
      v-model:visible="cleanupVisible"
      :header="cleanupBatch ? '批量清理前引用核对' : '清理前引用核对'"
      modal
      :style="{ width: '760px' }"
    >
      <div v-if="cleanupPlan" class="cleanup-plan">
        <p class="plan-intro">
          以下引用关系在移除前已全部列出。已被版本冻结或会签使用的对象会
          <strong>停用并保留历史</strong>，相关会签回到待重审；仅被草稿引用的条目将一并整理。
        </p>

        <section v-if="planDeleteItems.length" class="plan-section plan-delete">
          <h4>将彻底移除（仅草稿引用、未冻结） · {{ planDeleteItems.length }}</h4>
          <ul>
            <li v-for="item in planDeleteItems" :key="`del-${item.kind}-${item.id}`">
              <span class="plan-kind">{{ item.cascade ? '级联' : '目标' }}</span>
              {{ item.label }} <code>{{ item.id }}</code>
              <small>{{ item.reason }}</small>
            </li>
          </ul>
        </section>

        <section v-if="planDeactivateItems.length" class="plan-section plan-deactivate">
          <h4>将停用保留（版本冻结或会签使用） · {{ planDeactivateItems.length }}</h4>
          <ul>
            <li v-for="item in planDeactivateItems" :key="`off-${item.kind}-${item.id}`">
              <span class="plan-kind">{{ item.cascade ? '级联' : '目标' }}</span>
              {{ item.label }} <code>{{ item.id }}</code>
              <small>{{ item.reason }}</small>
            </li>
          </ul>
        </section>

        <section v-if="cleanupPlan.threats.length" class="plan-section">
          <h4>受影响威胁 · {{ cleanupPlan.threats.length }}</h4>
          <ul>
            <li v-for="threat in cleanupPlan.threats" :key="`thr-${threat.id}`">
              <Tag
                :value="threat.action === 'prune_draft' ? '草稿剪引用' : '回到待重审'"
                :severity="threat.action === 'prune_draft' ? 'secondary' : 'warn'"
              />
              <strong>{{ threat.code }} {{ threat.title }}</strong>
              <small v-if="threat.removedRefs.length">
                受影响引用：{{ threat.removedRefs.map((ref) => `${ref.kind} ${ref.label}`).join('；') }}
              </small>
            </li>
          </ul>
        </section>
      </div>
      <template #footer>
        <Button label="取消" severity="secondary" outlined @click="cleanupVisible = false" />
        <Button
          :label="cleanupBatch ? '开始批量处理' : '确认清理'"
          icon="pi pi-check"
          severity="danger"
          :loading="cleanupSubmitting"
          @click="confirmCleanup"
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
            :options="store.data.components.filter((item) => isActive(item.lifecycle))"
            option-label="name"
            option-value="id"
          />
        </div>
        <div class="field">
          <label>目标组件</label>
          <Select
            v-model="flowForm.targetId"
            :options="store.data.components.filter((item) => isActive(item.lifecycle))"
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
.resume-banner {
  display: flex;
  align-items: flex-start;
  gap: 13px;
  margin-bottom: 16px;
  padding: 14px 16px;
  border: 1px solid #f2c78f;
  border-left: 4px solid #d97706;
  border-radius: 6px;
  background: #fffaf0;
}

.resume-banner > i {
  margin-top: 2px;
  color: #b45309;
}

.resume-copy {
  display: grid;
  gap: 8px;
}

.resume-copy strong {
  font-size: 13px;
}

.resume-row {
  display: flex;
  align-items: center;
  gap: 10px;
  color: #7b5d2c;
  font-size: 12px;
}

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
  display: flex !important;
  flex-direction: row;
  align-items: center;
  gap: 10px;
}

.name-cell {
  display: flex;
  align-items: center;
  gap: 8px;
}

.action-stack {
  display: flex;
  align-items: center;
  gap: 4px;
}

.cleanup-plan {
  display: grid;
  gap: 14px;
}

.plan-intro {
  margin: 0;
  color: #515e73;
  font-size: 13px;
  line-height: 1.6;
}

.plan-section {
  border: 1px solid #e2e6ec;
  border-radius: 6px;
  padding: 12px 14px;
}

.plan-section h4 {
  margin: 0 0 10px;
  font-size: 13px;
}

.plan-delete {
  border-left: 3px solid #c64b39;
}

.plan-deactivate {
  border-left: 3px solid #b0851f;
}

.plan-section ul {
  display: grid;
  gap: 8px;
  margin: 0;
  padding-left: 0;
  list-style: none;
}

.plan-section li {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
  font-size: 12px;
  color: #2f3a4d;
}

.plan-section li small {
  flex-basis: 100%;
  color: #7b8699;
}

.plan-kind {
  padding: 1px 7px;
  border-radius: 10px;
  background: #eef2f7;
  color: #5d6b82;
  font-size: 10px;
}

.plan-section code {
  color: #8791a3;
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
</style>
