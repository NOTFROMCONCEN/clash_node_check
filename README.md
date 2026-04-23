# Clash Node Checker

一个使用 Rust + egui/eframe 搭建的 Clash / 常见代理 URI 订阅检测 GUI，当前重点是“节点可用性 + 传输质量 + 安全解释 + 订阅级启发式评估”。

## 当前版本支持

- 输入 Clash 订阅 URL 并下载订阅内容
- 解析 Clash YAML 中的 `proxies`
- 兼容常见 base64 / 标准 URI 订阅列表

  - 支持 trojan / vless / vmess / tuic / hysteria / hysteria2 的关键字段提取
  - 支持从 userinfo 中提取 uuid / password / auth 等认证字段
  - 支持解析 vmess base64 JSON 中的 server / port / uuid / TLS / ALPN / network
- 提取订阅级配置提示

  - 解析 DNS / TUN / rules / rule-providers / allow-lan / bind-address / controller / secret 等配置提示
- 基础探测与质量指标

  - DNS 解析检测
  - TCP 连通检测（多次采样、成功次数、平均耗时）
  - TCP 质量指标（抖动 jitter、丢包 loss）
  - UDP 可用性探测（成功 / 部分 / 失败 + 响应耗时）
  - TLS ClientHello 预检（可选，按协议自动筛选目标）
  - 首包时间 TTFB 基线探测（TLS / HTTP 首包）
  - 持续稳定性测试（30s / 60s 窗口，超时率 / 连续失败）
- 协议与安全解释层

  - 协议真实握手 v2：trojan / vless
  - 安全性评估（高 / 中 / 低，0~100 单节点评分）
  - 加密程度评估（强 / 中 / 弱 / 明文 / 未知）
  - 过GW能力评估与原因说明
  - 防追踪评估与原因说明
  - 现网稳定性评估与原因说明
- 订阅级汇总与 GUI

  - 订阅综合评分（可用性 / 安全性 / 传输质量 / 现网稳定性 / 订阅整洁度）
  - 本机私流安全启发式评估（基于订阅配置与节点特征，不是主动抓包）
  - 订阅质量检测（重复端点、重名节点、唯一端点统计）
  - 结果筛选与搜索（全部 / 通过 / 部分 / 失败 / 高风险）
  - 精简 / 完整两种表格模式
  - 节点详情窗口显示安全等级、加密等级、过GW、防追踪、现网稳定性及原因
  - 指标说明窗口支持滚动，程序主界面为响应式布局
  - 启动后自动检查 GitHub Release 更新，并支持手动跳转下载页

## 运行

```powershell
cargo run
```

## 验证

```powershell
cargo test
```

## 版本与更新

- 当前程序版本来自 `Cargo.toml`，GUI 标题栏和左侧“版本与更新”卡片会显示当前版本。
- 启动后会自动检查一次 GitHub Release 最新版本，也可以在界面中手动点击“检查更新”。
- 更新检测只负责发现新版本和跳转下载，不会在本地自动覆盖可执行文件。
- 默认 Release 源：`NOTFROMCONCEN/clash_node_check`

## 发版脚本

```powershell
.\scripts\preflight-sanitize.ps1
.\scripts\build-release.ps1
.\scripts\publish-github-release.ps1
```

- `preflight-sanitize.ps1`：扫描工作区和 Git 历史中常见敏感凭据形态，避免把明显 token / private key / 带鉴权参数 URL 推上 GitHub。
- `build-release.ps1`：执行 `cargo test`、`cargo build --release`，并在 `dist/` 目录生成 `.exe`、`.zip` 和 `sha256`。
- `publish-github-release.ps1`：设置/校验 `origin`，切到 `main`，提交当前改动，创建 `v<version>` tag，推送到 GitHub，并通过 `gh release create` 上传发行资产。
- 发布前需要本机已经安装并登录 GitHub CLI：`gh auth status`

## 当前版本边界

- 协议真实握手尚未补齐 vmess AEAD、tuic、hysteria / hysteria2、REALITY 细化路径。
- TTFB 当前是 TLS / HTTP 首包基线探测，不代表“经完整代理链访问真实业务 URL”的最终业务首包。
- TLS 与证书安全目前以 ClientHello 预检、`skip-cert-verify` 风险和 SNI / ALPN / REALITY 配置推断为主，尚未输出证书链、到期时间、域名匹配、自签状态、TLS 版本与握手失败子类型。
- “本机私流安全”当前是订阅配置 / 节点特征的启发式评估，不是主动 DNS 泄露测试，也没有私网流量抓包。
- 暂未接入吞吐测试、出口 IP / ASN / 地区核验、IPv4 / IPv6 能力检测、业务场景可达性、结果导出与历史对比。

## 后续可扩展方向

- 补齐 VMess AEAD 与 QUIC / REALITY 真实握手（tuic / hysteria2 / vless-reality 细化）
- 增加真实 DNS 泄露测试与业务场景 URL 探测
- 支持从本地 YAML 文件导入
- 导出检测结果 CSV / JSON
- 增加历史对比与回归告警
