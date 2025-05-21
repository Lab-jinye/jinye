# Git提交规范

## 提交格式
`<type>(<scope>): <subject>`

## 类型说明
- feat: 新功能
- fix: 问题修复
- docs: 文档变更
- style: 代码格式
- refactor: 重构
- perf: 性能优化
- test: 测试用例
- chore: 构建/依赖变更

## 范围(scope)
• storage: 规则存储相关
• ai: 安全AI引擎
• config: 配置管理

## 示例
```
feat(storage): 增加规则版本控制功能
- 实现规则版本历史存储
- 添加版本回滚API端点

chore(docs): 添加提交规范文档
- 创建COMMIT_CONVENTION.md
- 更新README中的贡献指南
```