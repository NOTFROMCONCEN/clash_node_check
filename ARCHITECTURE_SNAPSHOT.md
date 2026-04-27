# Clash Node Checker 架构快照（常驻）

更新时间：2026-04-27  
当前版本：`v1.6.0`

## 1. 产品定位

本项目是一个 Rust + egui/eframe 的桌面 GUI 检测器，用于对 Clash/URI 订阅节点进行：

- 连通性检测（DNS/TCP/TLS/UDP）
- 传输质量检测（延迟/抖动/丢包/TTFB/稳定性）
- 协议探测（trojan/vless/vmess/tuic/hysteria2/hysteria）
- 安全解释与评分（单节点 + 订阅级）
- 主流客户端批量导入导出（Karing / FlClash / Clash）

## 2. 代码结构

- `src/main.rs`：程序入口、窗口参数、启动 `ClashCheckerApp`
- `src/app.rs`：UI 层（控制面板、结果表格、筛选、详情窗口、指标说明、更新卡片）
- `src/checker.rs`：检测引擎（并发调度、各类探测、状态聚合、评分）
- `src/client_io.rs`：数据入口/出口（在线 URL、本地批量导入、客户端导出）
- `src/subscription.rs`：订阅解析（Clash YAML / base64 / 标准 URI）
- `src/update.rs`：GitHub Release 更新检查与版本比较（`releases/latest` 跳转解析 + atom 兜底 + 本地缓存）

## 3. 核心数据流

1. UI 输入订阅 URL 或本地路径 + 检测参数，触发 `start_check(...)`  
2. `client_io` 统一导入来源（在线订阅/本地批量扫描），再进入 `parse_subscription(...)`  
3. 先发 `CheckEvent::Started(summary)`，再并发逐节点检测并发回 `NodeFinished`  
4. UI 增量更新统计与表格，最终收到 `Finished` 或 `Failed`  
5. 可双击节点打开详情窗口查看完整指标与解释

## 4. 探测与判定模型（当前）

- TCP：多次采样，输出成功次数、均值、抖动、丢包
- TLS：ClientHello 预检 + 协议条件约束
- UDP：通过 / 部分 / 失败 / 跳过
- TTFB：
  - `trojan/vless`：代理链 HTTP 首包
  - 其他：TLS/HTTP 基线或跳过
- 稳定性：30s/60s（可关闭）
- 协议探测：
  - 已有真实路径：`trojan` / `vless` / `vmess TCP AEAD` / `tuic` / `hysteria2`
  - `hysteria`：QUIC 连接尝试（传输层）

状态聚合：

- `Fail`：TCP 不可达 / 协议探测失败 /（UDP 必需协议且 UDP 失败）
- `Warn`：TLS 失败、采样不满、协议部分/跳过、UDP 风险、TTFB 风险、稳定性低
- `Pass`：其余健康路径

## 5. 评分体系（当前）

- 单节点：安全等级 + 加密等级 + 解释文本 + `0~100` 分
- 订阅级：可用性 / 安全性 / 传输质量 / 现网稳定 / 订阅整洁度 加权聚合
- 本机私流：订阅级启发式评估（非真实抓包）

## 6. UI 现状（v1.5.9）

- 响应式布局：窄屏单列，宽屏左右工作区
- 表格模式：精简 / 完整
- 结果筛选：全部 / 通过 / 部分 / 失败 / 高风险
- 搜索：节点名/服务器/原因
- 详情：双击行打开可滚动详细窗口
- 指标说明：菜单栏入口，滚动阅读
- 导出：按预设导出 Clash / FlClash / Karing 可用节点配置

## 7. 发布与运维

- 本地脚本：
  - `scripts/preflight-sanitize.ps1`
  - `scripts/build-release.ps1`
  - `scripts/publish-github-release.ps1`
- CI/CD：`.github/workflows/release.yml`（`v*` tag 自动 Windows 构建并发布 Release 资产）

## 8. 测试与质量

- 当前已含单元测试（`cargo test` 可通过）
- `cargo check` 依赖本机 MSVC `link.exe` 环境

## 9. 已知边界（当前）

- `hysteria` 应用层认证未补齐
- REALITY/XTLS 专用客户端路径未补齐
- TLS 证书链细项审计（到期、域名匹配、自签等）未完成
- 吞吐、出口信息、IPv4/IPv6、真实 DNS 泄漏、业务可达性尚未接入
- ZIP 直读导入当前未启用（需先解压后导入目录）

## 10. 维护约定（以后都按这个）

- 每次做大需求前先更新本文件“更新时间/版本/边界”
- 每次完成里程碑后同步本文件“探测能力/评分模型/发布链路”
- 本文件作为后续需求评估、回归测试、发版说明的唯一架构基线
