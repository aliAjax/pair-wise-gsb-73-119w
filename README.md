# SCAPEX 安全威胁建模与缓解措施会签平台

基于 Vue 3、PrimeVue、Pinia、Vue Router、Apollo Client、GraphQL、Vite 与 TypeScript 的独立前端工程。项目不依赖真实后端，GraphQL 查询通过自定义 `ApolloLink` 映射到浏览器 `localStorage` 中的本地仓库。

## 功能

- 系统边界、信任区、组件资产、外部依赖与数据流建模
- 由当前模型状态实时渲染的数据流图
- 威胁、攻击路径、控制、风险与组件/数据流关联
- 未覆盖组件、控制失效、证据缺失、风险接受过期与缓解冲突检查
- 5 x 5 风险矩阵、风险接受条件与有效期
- 开发、安全、业务三方逐项会签
- 版本快照、版本差异与受影响威胁限定重新审核
- 控制证据有效期管理、审计轨迹与 Markdown 报告导出
- 全部修改自动持久化到 `localStorage`

## 架构清理与引用一致性

- 移除组件/数据流/依赖前，先弹出引用关系影响分析（威胁、控制、数据流、缓解任务、证据、会签、版本）
- 只被草稿引用的条目随清理一并整理；被版本冻结或会签使用的对象转「停用」并保留历史
- 引用被解除的威胁自动回到待重审（修订号 +1），并纳入当前版本会签范围
- 每次清理是一个批量任务：逐项落库，中途失败可在下次打开或页面横幅中恢复未完成项
- 多窗口并发：基于变更计数的乐观守卫 + `storage` 事件同步，后提交的一方会看到引用已变化
- 旧数据首次打开自动迁移：补齐生命周期标记、清理悬空引用、失宿主对象转停用
- 页面、图谱、风险汇总、GraphQL 指标与导出报告统一使用 `src/services/selectors.ts` 的活跃口径

## 运行

```bash
npm install
npm run dev
```

默认开发地址为 `http://localhost:18473`。

## 构建

```bash
npm run build
```

## 校验

```bash
npm run verify
```

编译领域服务后在 Node 中跑 5 组场景（首启迁移、停用级联、草稿一并整理、批量任务断点恢复、双窗口并发），共 45 项断言。

## GraphQL

`src/graphql/client.ts` 使用 Apollo Client 的自定义 `ApolloLink`。当前注册以下真实查询操作：

- `DashboardMetrics`
- `ThreatIndex`
- `ControlHealth`

工作台指标通过 Apollo Client 查询，其余业务状态由 Pinia 管理并持久化。
