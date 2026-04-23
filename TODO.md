# Clash Node Checker TODO

> 目标：把节点评测从“连通性”升级到“可用性 + 稳定性 + 安全性 + 场景适配”。

## 当前状态核对（2026-04）

- 已完成：UDP 可用性、抖动/丢包、持续稳定性、TTFB 基线探测、标准 URI 订阅关键字段解析增强、订阅综合评分、过GW/防追踪/现网稳定性画像、本机私流安全启发式评估、GUI 解释层与详情原因展示、GitHub Release 更新检测、Windows 本地发版脚本。
- 部分完成：协议真实握手目前覆盖 trojan / vless；证书与 TLS 细项目前仅做到策略风险提示与 ClientHello 预检；DNS 泄露目前仅做到订阅配置/节点特征的启发式评估。
- 未完成：vmess AEAD 与 QUIC/REALITY 真实握手、吞吐测试、证书链/到期/域名匹配审计、出口信息、IPv4/IPv6、真实 DNS 泄露测试、业务场景可达性。

## Phase A - 核心可用性（优先做）

- [ ] 1. 协议真实握手测试（trojan/vmess/vless/hysteria2/tuic）
  - 验收：每种协议至少 1 条真实握手路径，失败原因可分类展示。
  - 进展：已完成 v2（trojan/vless 真实握手路径 + TLS 真实握手写入校验 + 失败原因分类）；已补齐标准 URI 订阅关键字段解析（trojan/vless/vmess/tuic/hysteria/hysteria2），为后续 vmess AEAD 与 QUIC/REALITY 实握手打通输入面；待补齐 vmess AEAD、tuic/hysteria/hysteria2 与 REALITY 细化实握手。
- [x] 2. UDP 可用性测试
  - 验收：输出 UDP 成功/失败与耗时，并入总体评分。
- [x] 3. 抖动与丢包统计
  - 验收：新增 `jitter`、`loss` 指标，支持按时间窗口采样。
- [x] 4. 持续稳定性测试（30s/60s）
  - 验收：输出超时率、连续失败次数、可视化稳定等级。
- [x] 5. 标准 URI 订阅关键字段解析增强（trojan/vless/vmess/tuic/hysteria/hysteria2）
  - 验收：userinfo / query / vmess base64 JSON 中的关键认证字段能够进入后续检测链路。

## Phase B - 性能与传输质量

- [x] 6. 首包时间（TTFB）测试（基线版）
  - 验收：经节点访问测试 URL，记录连接时间与首包时间。
  - 进展：已支持 TLS/HTTP 首包时间基线探测；后续补充“通过完整代理链访问业务 URL”的真实 TTFB。
- [ ] 7. 吞吐测试（轻量）
  - 验收：支持小流量测速（可配置），显示峰值/平均带宽。

## Phase C - TLS 与安全细项

- [ ] 8. 证书安全测试
  - 验收：证书链、到期时间、域名匹配、自签状态可展示。
  - 进展：已把 `skip-cert-verify` / 证书校验策略纳入风险提示与评分，但尚未输出证书链、到期时间、域名匹配、自签状态。
- [ ] 9. TLS 细项检测
  - 验收：显示 TLS 版本、ALPN、握手失败子类型。
  - 进展：已展示 TLS ClientHello 预检结果，并结合 SNI / ALPN / REALITY 做安全推断；尚未输出真实 TLS 版本与握手失败子类型。

## Phase D - 出口与网络能力

- [x] 10. 过GW / 防追踪 / 现网稳定性画像
  - 验收：输出过GW、防追踪、现网稳定性等级与原因，并纳入结果解释层。
- [ ] 11. 出口信息核验（IP/ASN/国家地区）
  - 验收：节点名与出口信息差异可提示风险。
- [ ] 12. IPv4/IPv6 能力检测
  - 验收：分别给出 v4/v6 成功率与评分。
- [ ] 13. DNS 泄漏检测
  - 验收：检测是否走本地 DNS，给出泄漏风险等级。
  - 进展：已提供“本机私流安全”订阅级启发式评估，会综合 DNS / 规则 / TUN / 控制口 / 节点特征给出风险说明；尚未执行真实 DNS 泄露请求或抓包。

## Phase E - 业务场景能力

- [ ] 14. 业务场景可达性（Google/YouTube/OpenAI/GitHub 等）
  - 验收：可配置目标清单，输出场景通过率。

## Phase F - 解释层与订阅级汇总

- [x] 15. 订阅综合评分
  - 验收：从可用性、安全性、传输质量、现网稳定性、订阅整洁度聚合出订阅级评分与评级。
- [x] 16. 本机私流安全评估（启发式）
  - 验收：基于 Clash YAML 的 DNS / 规则 / TUN / 控制口配置与节点特征，给出订阅级私流风险等级与原因。
- [x] 17. GUI 解释层与说明文档
  - 验收：指标说明、节点详情、悬浮提示与摘要文案能够明确说明分数来源、评估原因和当前版本边界。

## Phase G - 发布与更新

- [x] 18. GitHub Release 更新检测
  - 验收：启动后自动检查最新 release，界面中可手动复查并跳转到下载页。
- [x] 19. Windows Release 打包脚本
  - 验收：执行脚本后生成 release exe、zip 和校验文件。
- [x] 20. GitHub 推送与 Release 发布脚本
  - 验收：通过本地脚本完成脱敏预检、commit、tag、push 和 `gh release create` 上传。
- [x] 21. GitHub Actions Tag 自动发版（Windows）
  - 验收：推送 `v*` tag 后自动执行 Windows 构建并上传 `.exe` / `.zip` / `sha256` 到 GitHub Release。

## 交付节奏

- 每完成 1 项：
  - 更新本文件勾选状态
  - 更新 README 指标说明
  - 提交一个独立 checkpoint（commit + tag）

## 当前建议顺序

1. 协议真实握手测试（优先补 vmess AEAD / QUIC / REALITY）  
2. 证书安全与 TLS 细项  
3. 出口信息 / IPv4 / IPv6 / 真实 DNS 泄漏  
4. 吞吐测试与业务场景可达性
