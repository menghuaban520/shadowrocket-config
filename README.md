# Shadowrocket Config

梦花瓣自用 Shadowrocket 配置。当前实际使用文件为 **`花花最终版.conf`**。

## 下载 / 导入

配置 Raw 地址：

`https://raw.githubusercontent.com/menghuaban520/shadowrocket-config/main/%E8%8A%B1%E8%8A%B1%E6%9C%80%E7%BB%88%E7%89%88.conf`

在 Shadowrocket 的配置页面通过 URL 下载即可。

## 仓库结构

- `花花最终版.conf`：当前实际使用的完整配置，自动分析不会修改它。
- `classified/CONFIG-INDEX.md`：配置区块、规则数量、重复规则、敏感字段启发式检查。
- `classified/RULES-REVIEW.md`：DIRECT / REJECT / PROXY 与规则类型的分类、重复项和候选策略冲突。
- `classified/SAFE-SECTIONS.md`：General / Host 的安全预览，疑似敏感值自动隐藏。
- `tools/`：只读分析脚本。
- `.github/workflows/classify.yml`：配置变化后自动重新生成分类报告。

## 当前概况

- 149,257 条有效规则
- 111,496 条 DIRECT
- 37,697 条 REJECT
- 64 条 PROXY
- 176 条完全重复的额外规则
- 5 组候选策略冲突

> Shadowrocket 规则按顺序匹配。当前自动分类只做分析，不会为了“看起来整齐”而重排实际规则，避免改变分流行为。
