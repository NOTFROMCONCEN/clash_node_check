use std::collections::{HashSet, VecDeque};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::subscription::{parse_subscription, ProxyNode};

#[derive(Clone, Debug)]
pub struct CheckOptions {
    pub timeout: Duration,
    pub attempts: u8,
    pub workers: usize,
    pub enable_tls_probe: bool,
}

impl Default for CheckOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(4),
            attempts: 3,
            workers: 24,
            enable_tls_probe: true,
        }
    }
}

#[derive(Clone, Debug)]
pub enum CheckEvent {
    Started(StartSummary),
    NodeFinished(NodeCheckResult),
    Finished,
    Failed(String),
}

#[derive(Clone, Debug, Default)]
pub struct StartSummary {
    pub total: usize,
    pub unique_endpoints: usize,
    pub duplicate_endpoints: usize,
    pub duplicate_names: usize,
    pub tls_target_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeStatus {
    Pass,
    Warn,
    Fail,
}

impl NodeStatus {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Pass => "通过",
            Self::Warn => "部分",
            Self::Fail => "失败",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TlsProbeStatus {
    Disabled,
    Skipped(String),
    Passed,
    Failed(String),
}

impl TlsProbeStatus {
    pub fn short_label(&self) -> String {
        match self {
            Self::Disabled => "关闭".to_owned(),
            Self::Skipped(reason) => format!("跳过({reason})"),
            Self::Passed => "通过".to_owned(),
            Self::Failed(reason) => format!("失败({reason})"),
        }
    }

    pub fn is_passed(&self) -> bool {
        matches!(self, Self::Passed)
    }
}

#[derive(Clone, Debug)]
pub struct NodeCheckResult {
    pub node: ProxyNode,
    pub status: NodeStatus,
    pub dns_ok: bool,
    pub tcp_successes: usize,
    pub tcp_attempts: usize,
    pub tcp_avg_latency_ms: Option<u128>,
    pub tls_status: TlsProbeStatus,
    pub tls_latency_ms: Option<u128>,
    pub message: String,
}

impl NodeCheckResult {
    pub fn tcp_alive(&self) -> bool {
        self.tcp_successes > 0
    }
}

pub fn start_check(subscription_url: String, options: CheckOptions, tx: Sender<CheckEvent>) {
    thread::spawn(move || {
        let result = run_check(&subscription_url, options, &tx);
        if let Err(error) = result {
            let _ = tx.send(CheckEvent::Failed(error));
        }
    });
}

fn run_check(
    subscription_url: &str,
    options: CheckOptions,
    tx: &Sender<CheckEvent>,
) -> Result<(), String> {
    let content = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(20))
        .user_agent("clash-node-checker/0.1")
        .build()
        .map_err(|error| format!("创建 HTTP 客户端失败：{error}"))?
        .get(subscription_url)
        .send()
        .map_err(|error| format!("下载订阅失败：{error}"))?
        .error_for_status()
        .map_err(|error| format!("订阅地址返回错误：{error}"))?
        .text()
        .map_err(|error| format!("读取订阅内容失败：{error}"))?;

    let nodes = parse_subscription(&content)?;
    let summary = summarize_subscription(&nodes);
    tx.send(CheckEvent::Started(summary))
        .map_err(|error| error.to_string())?;

    let queue = Arc::new(Mutex::new(VecDeque::from(nodes)));
    let worker_count = options.workers.max(1);
    let mut handles = Vec::new();

    for _ in 0..worker_count {
        let node_tx = tx.clone();
        let node_options = options.clone();
        let node_queue = Arc::clone(&queue);
        handles.push(thread::spawn(move || loop {
            let maybe_node = {
                let mut queue_guard = node_queue.lock().expect("queue poisoned");
                queue_guard.pop_front()
            };

            let Some(node) = maybe_node else {
                break;
            };

            let result = check_node(node, &node_options);
            let _ = node_tx.send(CheckEvent::NodeFinished(result));
        }));
    }

    for handle in handles {
        let _ = handle.join();
    }

    tx.send(CheckEvent::Finished)
        .map_err(|error| error.to_string())
}

fn check_node(node: ProxyNode, options: &CheckOptions) -> NodeCheckResult {
    let address = format!("{}:{}", node.server, node.port);
    let socket_addrs = match address.to_socket_addrs() {
        Ok(addrs) => addrs.collect::<Vec<_>>(),
        Err(error) => return dns_failed(node, format!("DNS 解析失败：{error}"), options.attempts),
    };

    if socket_addrs.is_empty() {
        return dns_failed(node, "没有可用地址".to_owned(), options.attempts);
    }

    let resolved_ip_count = socket_addrs
        .iter()
        .map(SocketAddr::ip)
        .collect::<HashSet<_>>()
        .len();
    let tcp_probe = run_tcp_probe(&socket_addrs, options.attempts.max(1), options.timeout);
    let tls_probe = run_tls_probe(&node, &socket_addrs, options, tcp_probe.success_addr);

    build_result(
        node,
        resolved_ip_count,
        tcp_probe,
        tls_probe,
        options.attempts.max(1),
    )
}

fn summarize_subscription(nodes: &[ProxyNode]) -> StartSummary {
    let mut endpoint_set = HashSet::new();
    let mut name_set = HashSet::new();
    let mut duplicate_names = 0usize;
    let mut tls_target_count = 0usize;

    for node in nodes {
        endpoint_set.insert(format!("{}:{}", node.server, node.port));
        if !name_set.insert(node.name.clone()) {
            duplicate_names += 1;
        }
        if should_probe_tls(&node.node_type) {
            tls_target_count += 1;
        }
    }

    let unique_endpoints = endpoint_set.len();
    let duplicate_endpoints = nodes.len().saturating_sub(unique_endpoints);

    StartSummary {
        total: nodes.len(),
        unique_endpoints,
        duplicate_endpoints,
        duplicate_names,
        tls_target_count,
    }
}

fn dns_failed(node: ProxyNode, reason: String, attempts: u8) -> NodeCheckResult {
    NodeCheckResult {
        node,
        status: NodeStatus::Fail,
        dns_ok: false,
        tcp_successes: 0,
        tcp_attempts: attempts as usize,
        tcp_avg_latency_ms: None,
        tls_status: TlsProbeStatus::Skipped("DNS失败".to_owned()),
        tls_latency_ms: None,
        message: reason,
    }
}

#[derive(Clone, Debug, Default)]
struct TcpProbe {
    successes: usize,
    latencies_ms: Vec<u128>,
    success_addr: Option<SocketAddr>,
    last_error: Option<String>,
}

fn run_tcp_probe(socket_addrs: &[SocketAddr], attempts: u8, timeout: Duration) -> TcpProbe {
    let mut probe = TcpProbe::default();

    for _ in 0..attempts {
        let mut this_round_ok = false;
        for socket_addr in socket_addrs {
            let started_at = Instant::now();
            match TcpStream::connect_timeout(socket_addr, timeout) {
                Ok(_) => {
                    probe.successes += 1;
                    probe.latencies_ms.push(started_at.elapsed().as_millis());
                    if probe.success_addr.is_none() {
                        probe.success_addr = Some(*socket_addr);
                    }
                    this_round_ok = true;
                    break;
                }
                Err(error) => {
                    probe.last_error = Some(error.to_string());
                }
            }
        }

        if !this_round_ok && probe.last_error.is_none() {
            probe.last_error = Some("连接失败".to_owned());
        }
    }

    probe
}

fn run_tls_probe(
    node: &ProxyNode,
    socket_addrs: &[SocketAddr],
    options: &CheckOptions,
    prefer_addr: Option<SocketAddr>,
) -> TlsProbeStatusWithLatency {
    if !options.enable_tls_probe {
        return TlsProbeStatusWithLatency {
            status: TlsProbeStatus::Disabled,
            latency_ms: None,
        };
    }

    if !should_probe_tls(&node.node_type) {
        return TlsProbeStatusWithLatency {
            status: TlsProbeStatus::Skipped("协议默认跳过".to_owned()),
            latency_ms: None,
        };
    }

    if node.server.parse::<IpAddr>().is_ok() {
        return TlsProbeStatusWithLatency {
            status: TlsProbeStatus::Skipped("IP地址".to_owned()),
            latency_ms: None,
        };
    }

    let mut ordered_addrs = Vec::with_capacity(socket_addrs.len());
    if let Some(addr) = prefer_addr {
        ordered_addrs.push(addr);
    }
    for addr in socket_addrs {
        if Some(*addr) != prefer_addr {
            ordered_addrs.push(*addr);
        }
    }

    let mut last_error = "TLS 握手失败".to_owned();

    for addr in ordered_addrs {
        let mut tcp_stream = match TcpStream::connect_timeout(&addr, options.timeout) {
            Ok(stream) => stream,
            Err(error) => {
                last_error = format!("TLS TCP 连接失败: {error}");
                continue;
            }
        };

        let _ = tcp_stream.set_read_timeout(Some(options.timeout));
        let _ = tcp_stream.set_write_timeout(Some(options.timeout));
        let started_at = Instant::now();

        match tls_client_hello_probe(&mut tcp_stream, options.timeout) {
            Ok(_) => {
                return TlsProbeStatusWithLatency {
                    status: TlsProbeStatus::Passed,
                    latency_ms: Some(started_at.elapsed().as_millis()),
                }
            }
            Err(error) => {
                last_error = error.to_string();
            }
        }
    }

    TlsProbeStatusWithLatency {
        status: TlsProbeStatus::Failed(last_error),
        latency_ms: None,
    }
}

fn tls_client_hello_probe(stream: &mut TcpStream, _timeout: Duration) -> Result<(), String> {
    let client_hello = build_client_hello_packet();
    stream
        .write_all(&client_hello)
        .map_err(|error| format!("发送ClientHello失败: {error}"))?;
    stream
        .flush()
        .map_err(|error| format!("刷新ClientHello失败: {error}"))?;

    let mut header = [0_u8; 5];
    stream
        .read_exact(&mut header)
        .map_err(|error| format!("读取TLS响应失败: {error}"))?;

    let is_tls_record = matches!(header[0], 0x14..=0x17) && header[1] == 0x03;
    if is_tls_record {
        Ok(())
    } else {
        Err(format!(
            "响应不是TLS记录头: {:02X} {:02X} {:02X} {:02X} {:02X}",
            header[0], header[1], header[2], header[3], header[4]
        ))
    }
}

fn build_client_hello_packet() -> Vec<u8> {
    let mut packet = Vec::with_capacity(52);
    packet.extend_from_slice(&[0x16, 0x03, 0x01, 0x00, 0x2F]);
    packet.extend_from_slice(&[0x01, 0x00, 0x00, 0x2B]);
    packet.extend_from_slice(&[0x03, 0x03]);

    let now = Instant::now().elapsed().as_nanos() as u64;
    let mut random = [0_u8; 32];
    for (index, byte) in random.iter_mut().enumerate() {
        let shifted = now.rotate_left((index % 32) as u32);
        *byte = ((shifted >> (index % 8)) & 0xFF) as u8;
    }
    packet.extend_from_slice(&random);

    packet.push(0x00);
    packet.extend_from_slice(&[0x00, 0x02, 0x00, 0x2F]);
    packet.extend_from_slice(&[0x01, 0x00]);
    packet.extend_from_slice(&[0x00, 0x00]);
    packet
}

#[derive(Clone, Debug)]
struct TlsProbeStatusWithLatency {
    status: TlsProbeStatus,
    latency_ms: Option<u128>,
}

fn build_result(
    node: ProxyNode,
    resolved_ip_count: usize,
    tcp_probe: TcpProbe,
    tls_probe: TlsProbeStatusWithLatency,
    attempts: u8,
) -> NodeCheckResult {
    let tcp_avg_latency_ms = average(&tcp_probe.latencies_ms);
    let tcp_ok = tcp_probe.successes > 0;
    let tls_failed = matches!(tls_probe.status, TlsProbeStatus::Failed(_));

    let status = if !tcp_ok {
        NodeStatus::Fail
    } else if tls_failed || tcp_probe.successes < attempts as usize {
        NodeStatus::Warn
    } else {
        NodeStatus::Pass
    };

    let message = compose_message(
        resolved_ip_count,
        tcp_probe.successes,
        attempts as usize,
        tcp_avg_latency_ms,
        &tls_probe.status,
        tcp_probe.last_error.as_deref(),
    );

    NodeCheckResult {
        node,
        status,
        dns_ok: true,
        tcp_successes: tcp_probe.successes,
        tcp_attempts: attempts as usize,
        tcp_avg_latency_ms,
        tls_status: tls_probe.status,
        tls_latency_ms: tls_probe.latency_ms,
        message,
    }
}

fn compose_message(
    resolved_ip_count: usize,
    tcp_successes: usize,
    attempts: usize,
    tcp_avg_latency_ms: Option<u128>,
    tls_status: &TlsProbeStatus,
    last_tcp_error: Option<&str>,
) -> String {
    let mut parts = Vec::new();
    parts.push(format!("DNS {resolved_ip_count} IP"));
    parts.push(format!("TCP {tcp_successes}/{attempts}"));
    if let Some(avg_ms) = tcp_avg_latency_ms {
        parts.push(format!("均延迟 {avg_ms}ms"));
    } else if let Some(error) = last_tcp_error {
        parts.push(format!("TCP失败 {error}"));
    }
    parts.push(format!("TLS {}", tls_status.short_label()));
    parts.join(" | ")
}

fn should_probe_tls(node_type: &str) -> bool {
    matches!(
        node_type.to_ascii_lowercase().as_str(),
        "trojan" | "https" | "tuic" | "hysteria" | "hysteria2" | "vless" | "vmess"
    )
}

fn average(values: &[u128]) -> Option<u128> {
    if values.is_empty() {
        None
    } else {
        Some(values.iter().sum::<u128>() / values.len() as u128)
    }
}
