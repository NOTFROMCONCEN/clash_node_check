<p align="center">
  <a href="https://linux.do">
    <img src="https://capsule-render.vercel.app/api?type=rect&height=210&color=0:0b0b0f,55:111827,100:c6a55a&text=linux.do&fontColor=f8fafc&fontSize=58&fontAlignY=40&desc=%E6%9E%81%E7%AE%80%E3%80%81%E6%9C%89%E6%96%99%E3%80%81%E5%80%BC%E5%BE%97%E7%82%B9%E5%BC%80&descAlignY=67" alt="linux.do 极简高端友链横幅" />
  </a>
</p>

<p align="center">
  CURATED FRIEND LINK
</p>

<p align="center">
  <a href="https://linux.do">
    <img src="https://img.shields.io/badge/Friend%20Link-linux.do-0f172a?style=for-the-badge&logo=linux&logoColor=ffffff&labelColor=c6a55a" alt="Friend Link to linux.do" />
  </a>
  <img src="https://img.shields.io/badge/Signal-High-0f172a?style=for-the-badge&labelColor=1f2937" alt="High Signal" />
  <img src="https://img.shields.io/badge/Quality-First-0f172a?style=for-the-badge&labelColor=374151" alt="Quality First" />
</p>

<p align="center">
  感谢 linux.do 社区长期输出高质量的技术讨论、实战经验与一手信息流；如果你偏爱克制但有料的内容，这个入口值得点开。
</p>

# Clash Node Checker

一个使用 Rust + egui/eframe 搭建的 Clash / 常见代理 URI 订阅检测 GUI，当前重点是“节点可用性 + 传输质量 + 安全解释 + 订阅级启发式评估”。

测试结果的优劣由您的本地网络环境直接关联，本程序最初目的也是测试某一订阅在当前网络环境下的优劣，推荐您购买各家代理服务商的最基础套餐进行测试。

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
  - 首包时间 TTFB 探测（trojan / vless 代理链 HTTP 首包，其余协议 TLS / HTTP 基线首包）
  - 持续稳定性测试（30s / 60s 窗口，超时率 / 连续失败）
- 协议与安全解释层

  - 协议真实握手：trojan / vless / vmess TCP AEAD / tuic / hysteria2
  - QUIC 连接尝试：hysteria
  - 安全性评估（高 / 中 / 低，0~100 单节点评分）
  - 加密程度评估（强 / 中 / 弱 / 明文 / 未知）
  - GFW 通过性评估与原因说明
  - 本地网络可达性评估与原因说明
  - 防追踪评估与原因说明
  - 现网稳定性评估与原因说明
- 订阅级汇总与 GUI

  - 订阅综合评分（可用性 / 安全性 / 传输质量 / 现网稳定性 / 订阅整洁度）
  - 本机私流安全启发式评估（基于订阅配置与节点特征，不是主动抓包）
  - 订阅质量检测（重复端点、重名节点、唯一端点统计）
  - 结果筛选与搜索（全部 / 通过 / 部分 / 失败 / 高风险）
  - 精简 / 完整两种表格模式
  - 节点详情窗口显示安全等级、加密等级、GFW 通过性、本地网络可达性、防追踪、现网稳定性及原因
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

## GitHub Actions 自动发版

- 已内置工作流：[.github/workflows/release.yml](.github/workflows/release.yml)
- 触发方式：
  - 推送 tag（`v*`）时：自动在 `windows-latest` 执行测试+打包，并发布 GitHub Release 资产。
  - 手动触发 `workflow_dispatch` 时：执行打包并上传 workflow artifacts（不自动发 Release）。
- 版本一致性校验：工作流会检查 `Cargo.toml` 版本是否与 tag 一致，例如 `version = "1.0.3"` 对应 tag `v1.0.3`。

示例：

```powershell
git tag v1.0.4
git push origin v1.0.4
```

## 当前版本边界

- 协议真实握手尚未补齐 hysteria 的应用层认证，以及 REALITY / XTLS 专用客户端路径；其中 hysteria v1 仍依赖自定义客户端协议栈，REALITY / XTLS 仍需 Xray/sing-box 级专用握手实现。
- TTFB 当前已支持 trojan / vless 通过代理链访问测试 URL 的 HTTP 首包；其余协议仍以 TLS / HTTP 首包基线探测为主。
- TLS 与证书安全目前以 ClientHello 预检、`skip-cert-verify` 风险和 SNI / ALPN / REALITY 配置推断为主，尚未输出证书链、到期时间、域名匹配、自签状态、TLS 版本与握手失败子类型。
- “本机私流安全”当前是订阅配置 / 节点特征的启发式评估，不是主动 DNS 泄露测试，也没有私网流量抓包。
- 暂未接入吞吐测试、出口 IP / ASN / 地区核验、IPv4 / IPv6 能力检测、业务场景可达性、结果导出与历史对比。

## 后续可扩展方向

- 补齐 hysteria 应用层认证与 REALITY / XTLS 专用客户端路径
- 增加真实 DNS 泄露测试与业务场景 URL 探测
- 支持从本地 YAML 文件导入
- 导出检测结果 CSV / JSON
- 增加历史对比与回归告警
