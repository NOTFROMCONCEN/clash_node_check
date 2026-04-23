# Clash Node Checker

一个使用 Rust + egui/eframe 搭建的 Clash 订阅节点存活检测 GUI 骨架。

当前版本支持：

- 输入 Clash 订阅 URL
- 下载订阅内容
- 解析 Clash YAML 中的 `proxies`
- 兼容常见 base64 URI 订阅列表的节点名、服务器和端口提取
- 对每个节点的 `server:port` 进行 TCP 存活探测
- 在 GUI 中展示总数、存活数、存活百分比和节点状态表

## 运行

```powershell
cargo run
```

## 后续可扩展方向

- 按协议实现真实代理握手检测
- 增加延迟测速和失败原因分类
- 支持从本地 YAML 文件导入
- 导出检测结果 CSV/JSON
- 设置并发数、超时时间和目标测试 URL
