use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::subscription::{parse_subscription, ProxyNode};

#[derive(Clone, Debug)]
pub struct CheckOptions {
    pub timeout: Duration,
    pub attempts: u8,
    pub workers: usize,
    pub enable_tls_probe: bool,
    pub stability_window_secs: u16,
}

impl Default for CheckOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(4),
            attempts: 3,
            workers: 24,
            enable_tls_probe: true,
            stability_window_secs: 0,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProtocolProbeStatus {
    Passed(String),
    Partial(String),
    Failed(String),
    Skipped(String),
}

impl ProtocolProbeStatus {
    pub fn short_label(&self) -> String {
        match self {
            Self::Passed(message) => format!("通过({message})"),
            Self::Partial(message) => format!("部分({message})"),
            Self::Failed(message) => format!("失败({message})"),
            Self::Skipped(message) => format!("跳过({message})"),
        }
    }

    pub fn is_passed(&self) -> bool {
        matches!(self, Self::Passed(_))
    }

    pub fn is_failed(&self) -> bool {
        matches!(self, Self::Failed(_))
    }
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
pub enum SecurityLevel {
    High,
    Medium,
    Low,
    Unknown,
}

impl SecurityLevel {
    pub fn label(&self) -> &'static str {
        match self {
            Self::High => "高",
            Self::Medium => "中",
            Self::Low => "低",
            Self::Unknown => "未知",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EncryptionLevel {
    Strong,
    Moderate,
    Weak,
    Plaintext,
    Unknown,
}

impl EncryptionLevel {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Strong => "强",
            Self::Moderate => "中",
            Self::Weak => "弱",
            Self::Plaintext => "明文",
            Self::Unknown => "未知",
        }
    }
}

#[derive(Clone, Debug)]
pub struct SecurityAssessment {
    pub security_level: SecurityLevel,
    pub encryption_level: EncryptionLevel,
    pub score: u8,
    pub note: String,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UdpProbeStatus {
    Passed(String),
    Partial(String),
    Failed(String),
    Skipped(String),
}

impl UdpProbeStatus {
    pub fn short_label(&self) -> String {
        match self {
            Self::Passed(message) => format!("通过({message})"),
            Self::Partial(message) => format!("部分({message})"),
            Self::Failed(message) => format!("失败({message})"),
            Self::Skipped(message) => format!("跳过({message})"),
        }
    }

    pub fn is_passed(&self) -> bool {
        matches!(self, Self::Passed(_))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TtfbProbeStatus {
    Passed(String),
    Failed(String),
    Skipped(String),
}

impl TtfbProbeStatus {
    pub fn short_label(&self) -> String {
        match self {
            Self::Passed(message) => format!("通过({message})"),
            Self::Failed(message) => format!("失败({message})"),
            Self::Skipped(message) => format!("跳过({message})"),
        }
    }

    pub fn is_passed(&self) -> bool {
        matches!(self, Self::Passed(_))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StabilityLevel {
    High,
    Medium,
    Low,
    Disabled,
}

impl StabilityLevel {
    pub fn label(&self) -> &'static str {
        match self {
            Self::High => "高",
            Self::Medium => "中",
            Self::Low => "低",
            Self::Disabled => "关闭",
        }
    }
}

#[derive(Clone, Debug)]
pub struct StabilityMetrics {
    pub window_secs: u16,
    pub samples: usize,
    pub failures: usize,
    pub timeout_rate_percent: f32,
    pub max_consecutive_failures: usize,
    pub level: StabilityLevel,
}

impl StabilityMetrics {
    fn disabled() -> Self {
        Self {
            window_secs: 0,
            samples: 0,
            failures: 0,
            timeout_rate_percent: 0.0,
            max_consecutive_failures: 0,
            level: StabilityLevel::Disabled,
        }
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
    pub tcp_jitter_ms: Option<u128>,
    pub tcp_loss_percent: f32,
    pub tls_status: TlsProbeStatus,
    pub tls_latency_ms: Option<u128>,
    pub udp_status: UdpProbeStatus,
    pub udp_latency_ms: Option<u128>,
    pub ttfb_status: TtfbProbeStatus,
    pub ttfb_ms: Option<u128>,
    pub stability: StabilityMetrics,
    pub protocol_probe: ProtocolProbeStatus,
    pub security: SecurityAssessment,
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

    let node_count = nodes.len();
    let queue = Arc::new(Mutex::new(VecDeque::from(nodes)));
    let worker_count = options.workers.max(1).min(node_count.max(1));
    let probe_cache = Arc::new(Mutex::new(HashMap::<String, EndpointProbeResult>::new()));
    let mut handles = Vec::new();

    for _ in 0..worker_count {
        let node_tx = tx.clone();
        let node_options = options.clone();
        let node_queue = Arc::clone(&queue);
        let node_probe_cache = Arc::clone(&probe_cache);
        handles.push(thread::spawn(move || loop {
            let maybe_node = {
                let mut queue_guard = node_queue.lock().expect("queue poisoned");
                queue_guard.pop_front()
            };

            let Some(node) = maybe_node else {
                break;
            };

            let result = check_node(node, &node_options, &node_probe_cache);
            let _ = node_tx.send(CheckEvent::NodeFinished(result));
        }));
    }

    for handle in handles {
        let _ = handle.join();
    }

    tx.send(CheckEvent::Finished)
        .map_err(|error| error.to_string())
}

fn check_node(
    node: ProxyNode,
    options: &CheckOptions,
    probe_cache: &Arc<Mutex<HashMap<String, EndpointProbeResult>>>,
) -> NodeCheckResult {
    let cache_key = endpoint_cache_key(&node);
    let cached_probe = {
        let guard = probe_cache.lock().expect("probe cache poisoned");
        guard.get(&cache_key).cloned()
    };

    let probe = if let Some(probe) = cached_probe {
        probe
    } else {
        let calculated = collect_endpoint_probe(&node, options);
        let mut guard = probe_cache.lock().expect("probe cache poisoned");
        guard
            .entry(cache_key)
            .or_insert_with(|| calculated.clone())
            .clone()
    };

    match probe {
        EndpointProbeResult::DnsFailed(reason) => dns_failed(
            node,
            reason,
            options.attempts,
            options.stability_window_secs,
        ),
        EndpointProbeResult::Probed {
            resolved_ip_count,
            tcp_probe,
            tls_probe,
            udp_probe,
            ttfb_probe,
            stability,
        } => build_result(
            node,
            resolved_ip_count,
            tcp_probe,
            tls_probe,
            udp_probe,
            ttfb_probe,
            stability,
            options.attempts.max(1),
        ),
    }
}

fn endpoint_cache_key(node: &ProxyNode) -> String {
    format!(
        "{}:{}|{}",
        node.server,
        node.port,
        node.node_type.to_ascii_lowercase()
    )
}

#[derive(Clone, Debug)]
enum EndpointProbeResult {
    DnsFailed(String),
    Probed {
        resolved_ip_count: usize,
        tcp_probe: TcpProbe,
        tls_probe: TlsProbeStatusWithLatency,
        udp_probe: UdpProbeStatusWithLatency,
        ttfb_probe: TtfbProbeStatusWithLatency,
        stability: StabilityMetrics,
    },
}

fn collect_endpoint_probe(node: &ProxyNode, options: &CheckOptions) -> EndpointProbeResult {
    let address = format!("{}:{}", node.server, node.port);
    let socket_addrs = match address.to_socket_addrs() {
        Ok(addrs) => addrs.collect::<Vec<_>>(),
        Err(error) => return EndpointProbeResult::DnsFailed(format!("DNS 解析失败：{error}")),
    };

    if socket_addrs.is_empty() {
        return EndpointProbeResult::DnsFailed("没有可用地址".to_owned());
    }

    let resolved_ip_count = socket_addrs
        .iter()
        .map(SocketAddr::ip)
        .collect::<HashSet<_>>()
        .len();
    let tcp_probe = run_tcp_probe(&socket_addrs, options.attempts.max(1), options.timeout);
    let tls_probe = run_tls_probe(node, &socket_addrs, options, tcp_probe.success_addr);
    let udp_probe = run_udp_probe(node, &socket_addrs, options.timeout, tcp_probe.success_addr);
    let ttfb_probe = run_ttfb_probe(node, &socket_addrs, &tls_probe, options.timeout);
    let stability = run_stability_probe(
        &socket_addrs,
        options.timeout,
        options.stability_window_secs,
    );

    EndpointProbeResult::Probed {
        resolved_ip_count,
        tcp_probe,
        tls_probe,
        udp_probe,
        ttfb_probe,
        stability,
    }
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

fn dns_failed(
    node: ProxyNode,
    reason: String,
    attempts: u8,
    stability_window_secs: u16,
) -> NodeCheckResult {
    let stability = if stability_window_secs == 0 {
        StabilityMetrics::disabled()
    } else {
        StabilityMetrics {
            window_secs: stability_window_secs,
            samples: stability_window_secs as usize,
            failures: stability_window_secs as usize,
            timeout_rate_percent: 100.0,
            max_consecutive_failures: stability_window_secs as usize,
            level: StabilityLevel::Low,
        }
    };

    NodeCheckResult {
        node,
        status: NodeStatus::Fail,
        dns_ok: false,
        tcp_successes: 0,
        tcp_attempts: attempts as usize,
        tcp_avg_latency_ms: None,
        tcp_jitter_ms: None,
        tcp_loss_percent: 100.0,
        tls_status: TlsProbeStatus::Skipped("DNS失败".to_owned()),
        tls_latency_ms: None,
        udp_status: UdpProbeStatus::Skipped("DNS失败".to_owned()),
        udp_latency_ms: None,
        ttfb_status: TtfbProbeStatus::Skipped("DNS失败".to_owned()),
        ttfb_ms: None,
        stability,
        protocol_probe: ProtocolProbeStatus::Skipped("DNS失败".to_owned()),
        security: SecurityAssessment {
            security_level: SecurityLevel::Unknown,
            encryption_level: EncryptionLevel::Unknown,
            score: 0,
            note: "无法评估：DNS失败".to_owned(),
        },
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

        match tls_client_hello_probe(&mut tcp_stream) {
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

fn tls_client_hello_probe(stream: &mut TcpStream) -> Result<(), String> {
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

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
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

#[derive(Clone, Debug)]
struct UdpProbeStatusWithLatency {
    status: UdpProbeStatus,
    latency_ms: Option<u128>,
}

#[derive(Clone, Debug)]
struct TtfbProbeStatusWithLatency {
    status: TtfbProbeStatus,
    latency_ms: Option<u128>,
}

fn run_udp_probe(
    node: &ProxyNode,
    socket_addrs: &[SocketAddr],
    timeout: Duration,
    prefer_addr: Option<SocketAddr>,
) -> UdpProbeStatusWithLatency {
    if !should_probe_udp(&node.node_type) {
        return UdpProbeStatusWithLatency {
            status: UdpProbeStatus::Skipped("协议默认跳过".to_owned()),
            latency_ms: None,
        };
    }

    if node.udp == Some(false) {
        return UdpProbeStatusWithLatency {
            status: UdpProbeStatus::Failed("配置禁用UDP".to_owned()),
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

    let mut last_error = String::new();
    let mut timeout_seen = false;

    for addr in ordered_addrs {
        let bind_addr = if addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = match UdpSocket::bind(bind_addr) {
            Ok(socket) => socket,
            Err(error) => {
                last_error = format!("UDP绑定失败：{error}");
                continue;
            }
        };

        let _ = socket.set_read_timeout(Some(timeout));
        let _ = socket.set_write_timeout(Some(timeout));

        if let Err(error) = socket.connect(addr) {
            last_error = format!("UDP连接失败：{error}");
            continue;
        }

        let started_at = Instant::now();
        if let Err(error) = socket.send(&[0x00]) {
            last_error = format!("UDP发送失败：{error}");
            continue;
        }

        let mut recv_buf = [0_u8; 1];
        match socket.recv(&mut recv_buf) {
            Ok(_) => {
                return UdpProbeStatusWithLatency {
                    status: UdpProbeStatus::Passed("收到UDP响应".to_owned()),
                    latency_ms: Some(started_at.elapsed().as_millis()),
                }
            }
            Err(error) => match error.kind() {
                ErrorKind::TimedOut | ErrorKind::WouldBlock => {
                    timeout_seen = true;
                    last_error = "UDP无响应".to_owned();
                }
                ErrorKind::ConnectionReset | ErrorKind::ConnectionRefused => {
                    last_error = format!("UDP端口不可达：{error}");
                }
                _ => {
                    last_error = format!("UDP读取失败：{error}");
                }
            },
        }
    }

    if timeout_seen {
        UdpProbeStatusWithLatency {
            status: UdpProbeStatus::Partial("UDP无响应(可能被静默丢弃)".to_owned()),
            latency_ms: None,
        }
    } else {
        UdpProbeStatusWithLatency {
            status: UdpProbeStatus::Failed(if last_error.is_empty() {
                "UDP探测失败".to_owned()
            } else {
                last_error
            }),
            latency_ms: None,
        }
    }
}

fn run_ttfb_probe(
    node: &ProxyNode,
    socket_addrs: &[SocketAddr],
    tls_probe: &TlsProbeStatusWithLatency,
    timeout: Duration,
) -> TtfbProbeStatusWithLatency {
    if should_probe_tls(&node.node_type) {
        return match &tls_probe.status {
            TlsProbeStatus::Passed => TtfbProbeStatusWithLatency {
                status: TtfbProbeStatus::Passed("TLS首包".to_owned()),
                latency_ms: tls_probe.latency_ms,
            },
            TlsProbeStatus::Failed(reason) => TtfbProbeStatusWithLatency {
                status: TtfbProbeStatus::Failed(format!("TLS首包失败：{reason}")),
                latency_ms: None,
            },
            TlsProbeStatus::Disabled => TtfbProbeStatusWithLatency {
                status: TtfbProbeStatus::Skipped("TLS检测关闭".to_owned()),
                latency_ms: None,
            },
            TlsProbeStatus::Skipped(reason) => TtfbProbeStatusWithLatency {
                status: TtfbProbeStatus::Skipped(format!("TLS跳过：{reason}")),
                latency_ms: None,
            },
        };
    }

    if !matches!(
        node.node_type.to_ascii_lowercase().as_str(),
        "http" | "socks" | "socks5"
    ) {
        return TtfbProbeStatusWithLatency {
            status: TtfbProbeStatus::Skipped("该协议未定义TTFB探测".to_owned()),
            latency_ms: None,
        };
    }

    let mut last_error = String::new();
    for addr in socket_addrs {
        match http_first_byte_probe(addr, &node.server, timeout) {
            Ok(latency_ms) => {
                return TtfbProbeStatusWithLatency {
                    status: TtfbProbeStatus::Passed("HTTP首包".to_owned()),
                    latency_ms: Some(latency_ms),
                }
            }
            Err(error) => {
                last_error = error;
            }
        }
    }

    TtfbProbeStatusWithLatency {
        status: TtfbProbeStatus::Failed(if last_error.is_empty() {
            "首包探测失败".to_owned()
        } else {
            last_error
        }),
        latency_ms: None,
    }
}

fn http_first_byte_probe(
    socket_addr: &SocketAddr,
    host: &str,
    timeout: Duration,
) -> Result<u128, String> {
    let mut stream =
        TcpStream::connect_timeout(socket_addr, timeout).map_err(|error| error.to_string())?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let request = format!("HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    let started_at = Instant::now();
    stream
        .write_all(request.as_bytes())
        .map_err(|error| format!("发送HTTP请求失败：{error}"))?;

    let mut first_byte = [0_u8; 1];
    stream
        .read_exact(&mut first_byte)
        .map_err(|error| format!("读取HTTP首包失败：{error}"))?;
    Ok(started_at.elapsed().as_millis())
}

fn run_stability_probe(
    socket_addrs: &[SocketAddr],
    timeout: Duration,
    window_secs: u16,
) -> StabilityMetrics {
    if window_secs == 0 {
        return StabilityMetrics::disabled();
    }

    let samples = window_secs as usize;
    let mut failures = 0usize;
    let mut consecutive_failures = 0usize;
    let mut max_consecutive_failures = 0usize;

    for index in 0..samples {
        let mut success = false;
        for addr in socket_addrs {
            if TcpStream::connect_timeout(addr, timeout).is_ok() {
                success = true;
                break;
            }
        }

        if success {
            consecutive_failures = 0;
        } else {
            failures += 1;
            consecutive_failures += 1;
            max_consecutive_failures = max_consecutive_failures.max(consecutive_failures);
        }

        if index + 1 < samples {
            thread::sleep(Duration::from_secs(1));
        }
    }

    let timeout_rate_percent = if samples == 0 {
        0.0
    } else {
        failures as f32 / samples as f32 * 100.0
    };

    let level = classify_stability_level(timeout_rate_percent, max_consecutive_failures);

    StabilityMetrics {
        window_secs,
        samples,
        failures,
        timeout_rate_percent,
        max_consecutive_failures,
        level,
    }
}

fn classify_stability_level(
    timeout_rate_percent: f32,
    max_consecutive_failures: usize,
) -> StabilityLevel {
    if timeout_rate_percent == 0.0 {
        StabilityLevel::High
    } else if timeout_rate_percent <= 15.0 && max_consecutive_failures <= 2 {
        StabilityLevel::Medium
    } else {
        StabilityLevel::Low
    }
}

fn build_result(
    node: ProxyNode,
    resolved_ip_count: usize,
    tcp_probe: TcpProbe,
    tls_probe: TlsProbeStatusWithLatency,
    udp_probe: UdpProbeStatusWithLatency,
    ttfb_probe: TtfbProbeStatusWithLatency,
    stability: StabilityMetrics,
    attempts: u8,
) -> NodeCheckResult {
    let tcp_avg_latency_ms = average(&tcp_probe.latencies_ms);
    let tcp_jitter_ms = jitter(&tcp_probe.latencies_ms);
    let tcp_loss_percent = loss_percent(tcp_probe.successes, attempts as usize);
    let tcp_ok = tcp_probe.successes > 0;
    let protocol_probe =
        run_protocol_probe(&node, &tls_probe.status, tcp_probe.successes, attempts);
    let protocol_name = node.node_type.to_ascii_lowercase();
    let udp_is_required = is_udp_required_protocol(&protocol_name);
    let protocol_failed = protocol_probe.is_failed();
    let protocol_partial = matches!(protocol_probe, ProtocolProbeStatus::Partial(_));
    let protocol_skipped = matches!(protocol_probe, ProtocolProbeStatus::Skipped(_));
    let tls_failed = matches!(tls_probe.status, TlsProbeStatus::Failed(_));
    let udp_failed = matches!(udp_probe.status, UdpProbeStatus::Failed(_));
    let udp_warn = matches!(
        udp_probe.status,
        UdpProbeStatus::Partial(_) | UdpProbeStatus::Skipped(_)
    );
    let ttfb_warn = matches!(ttfb_probe.status, TtfbProbeStatus::Failed(_));
    let stability_warn = matches!(stability.level, StabilityLevel::Low);

    let status = if !tcp_ok || protocol_failed || (udp_is_required && udp_failed) {
        NodeStatus::Fail
    } else if tls_failed
        || tcp_probe.successes < attempts as usize
        || protocol_partial
        || protocol_skipped
        || (!udp_is_required && udp_failed)
        || udp_warn
        || ttfb_warn
        || stability_warn
    {
        NodeStatus::Warn
    } else {
        NodeStatus::Pass
    };

    let message = compose_message(
        resolved_ip_count,
        tcp_probe.successes,
        attempts as usize,
        tcp_avg_latency_ms,
        tcp_jitter_ms,
        tcp_loss_percent,
        &tls_probe.status,
        &udp_probe.status,
        &ttfb_probe.status,
        &stability,
        &protocol_probe,
        tcp_probe.last_error.as_deref(),
    );
    let security = assess_security(
        &node,
        &tls_probe.status,
        &udp_probe.status,
        tcp_success_rate(tcp_probe.successes, attempts as usize),
        tcp_loss_percent,
        tcp_jitter_ms,
        &stability,
        attempts,
    );

    NodeCheckResult {
        node,
        status,
        dns_ok: true,
        tcp_successes: tcp_probe.successes,
        tcp_attempts: attempts as usize,
        tcp_avg_latency_ms,
        tcp_jitter_ms,
        tcp_loss_percent,
        tls_status: tls_probe.status,
        tls_latency_ms: tls_probe.latency_ms,
        udp_status: udp_probe.status,
        udp_latency_ms: udp_probe.latency_ms,
        ttfb_status: ttfb_probe.status,
        ttfb_ms: ttfb_probe.latency_ms,
        stability,
        protocol_probe,
        security,
        message,
    }
}

fn compose_message(
    resolved_ip_count: usize,
    tcp_successes: usize,
    attempts: usize,
    tcp_avg_latency_ms: Option<u128>,
    tcp_jitter_ms: Option<u128>,
    tcp_loss_percent: f32,
    tls_status: &TlsProbeStatus,
    udp_status: &UdpProbeStatus,
    ttfb_status: &TtfbProbeStatus,
    stability: &StabilityMetrics,
    protocol_probe: &ProtocolProbeStatus,
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
    if let Some(jitter_ms) = tcp_jitter_ms {
        parts.push(format!("抖动 {jitter_ms}ms"));
    }
    parts.push(format!("丢包 {:.1}%", tcp_loss_percent));
    parts.push(format!("TLS {}", tls_status.short_label()));
    parts.push(format!("UDP {}", udp_status.short_label()));
    parts.push(format!("TTFB {}", ttfb_status.short_label()));
    if !matches!(stability.level, StabilityLevel::Disabled) {
        parts.push(format!(
            "稳定性 {} {:.1}%超时",
            stability.level.label(),
            stability.timeout_rate_percent
        ));
    }
    parts.push(format!("协议 {}", protocol_probe.short_label()));
    parts.join(" | ")
}

fn run_protocol_probe(
    node: &ProxyNode,
    tls_status: &TlsProbeStatus,
    tcp_successes: usize,
    attempts: u8,
) -> ProtocolProbeStatus {
    let protocol = node.node_type.to_ascii_lowercase();

    if tcp_successes == 0 {
        return ProtocolProbeStatus::Failed("TCP不可达".to_owned());
    }

    if tcp_successes < attempts as usize {
        return ProtocolProbeStatus::Partial("TCP采样未全通过".to_owned());
    }

    match protocol.as_str() {
        "trojan" => {
            if node.password.is_none() {
                ProtocolProbeStatus::Failed("缺少 password".to_owned())
            } else if !matches!(tls_status, TlsProbeStatus::Passed) {
                ProtocolProbeStatus::Partial("需要TLS通过".to_owned())
            } else {
                ProtocolProbeStatus::Passed("password+TLS就绪".to_owned())
            }
        }
        "vmess" | "vless" => {
            if node.uuid.is_none() {
                ProtocolProbeStatus::Failed("缺少 uuid/id".to_owned())
            } else if node
                .security
                .as_deref()
                .is_some_and(|value| value.eq_ignore_ascii_case("none"))
            {
                ProtocolProbeStatus::Partial("security=none".to_owned())
            } else if node.tls == Some(true) && !matches!(tls_status, TlsProbeStatus::Passed) {
                ProtocolProbeStatus::Partial("TLS要求未满足".to_owned())
            } else if protocol == "vless"
                && node
                    .flow
                    .as_deref()
                    .is_some_and(|value| value.eq_ignore_ascii_case("xtls-rprx-vision"))
                && !matches!(tls_status, TlsProbeStatus::Passed)
            {
                ProtocolProbeStatus::Partial("VISION 需要 TLS/REALITY".to_owned())
            } else {
                ProtocolProbeStatus::Passed("身份字段完整".to_owned())
            }
        }
        "tuic" => {
            if node.uuid.is_none() || node.password.is_none() {
                ProtocolProbeStatus::Failed("缺少 uuid/password".to_owned())
            } else if node.udp == Some(false) {
                ProtocolProbeStatus::Failed("UDP被禁用".to_owned())
            } else if node.alpn.is_none() {
                ProtocolProbeStatus::Partial("建议配置 ALPN".to_owned())
            } else {
                ProtocolProbeStatus::Skipped("QUIC真实握手待实现".to_owned())
            }
        }
        "hysteria" | "hysteria2" => {
            if node.password.is_none() && node.uuid.is_none() {
                ProtocolProbeStatus::Failed("缺少认证字段".to_owned())
            } else if node.udp == Some(false) {
                ProtocolProbeStatus::Failed("UDP被禁用".to_owned())
            } else if node.alpn.is_none() {
                ProtocolProbeStatus::Partial("建议配置 ALPN".to_owned())
            } else {
                ProtocolProbeStatus::Skipped("QUIC真实握手待实现".to_owned())
            }
        }
        _ => ProtocolProbeStatus::Skipped("该协议未配置握手探测".to_owned()),
    }
}

fn should_probe_tls(node_type: &str) -> bool {
    matches!(
        node_type.to_ascii_lowercase().as_str(),
        "trojan" | "https" | "tuic" | "hysteria" | "hysteria2" | "vless" | "vmess"
    )
}

fn should_probe_udp(node_type: &str) -> bool {
    matches!(
        node_type.to_ascii_lowercase().as_str(),
        "trojan"
            | "tuic"
            | "hysteria"
            | "hysteria2"
            | "vless"
            | "vmess"
            | "ss"
            | "socks"
            | "socks5"
    )
}

fn is_udp_required_protocol(node_type: &str) -> bool {
    matches!(node_type, "tuic" | "hysteria" | "hysteria2")
}

fn average(values: &[u128]) -> Option<u128> {
    if values.is_empty() {
        None
    } else {
        Some(values.iter().sum::<u128>() / values.len() as u128)
    }
}

fn jitter(values: &[u128]) -> Option<u128> {
    if values.len() < 2 {
        return None;
    }

    let mut diff_sum = 0_u128;
    for pair in values.windows(2) {
        diff_sum += pair[1].abs_diff(pair[0]);
    }
    Some(diff_sum / (values.len().saturating_sub(1) as u128))
}

fn loss_percent(successes: usize, attempts: usize) -> f32 {
    if attempts == 0 {
        0.0
    } else {
        ((attempts.saturating_sub(successes)) as f32 / attempts as f32) * 100.0
    }
}

fn tcp_success_rate(successes: usize, attempts: usize) -> f32 {
    if attempts == 0 {
        0.0
    } else {
        successes as f32 / attempts as f32
    }
}

fn assess_security(
    node: &ProxyNode,
    tls_status: &TlsProbeStatus,
    udp_status: &UdpProbeStatus,
    tcp_success_rate: f32,
    tcp_loss_percent: f32,
    tcp_jitter_ms: Option<u128>,
    stability: &StabilityMetrics,
    attempts: u8,
) -> SecurityAssessment {
    let protocol = node.node_type.to_ascii_lowercase();
    let mut notes = Vec::new();

    let (encryption_level, encryption_score) =
        encryption_strength(node, tls_status, &protocol, &mut notes);
    let transport_score = protocol_security_score(&protocol);
    let tls_score = tls_security_score(tls_status, &protocol, &mut notes);
    let udp_score = udp_security_score(udp_status, &protocol, &mut notes);
    let cert_score = cert_validation_score(node.skip_cert_verify, &mut notes);
    let metadata_score = metadata_security_score(node, &protocol, &mut notes);
    let reliability_score = (tcp_success_rate.clamp(0.0, 1.0) * 10.0).round() as u8;
    let loss_score = if tcp_loss_percent <= 5.0 {
        6
    } else if tcp_loss_percent <= 15.0 {
        4
    } else {
        notes.push(format!("TCP 丢包偏高 ({tcp_loss_percent:.1}%)"));
        1
    };
    let jitter_score = match tcp_jitter_ms {
        Some(jitter) if jitter <= 8 => 6,
        Some(jitter) if jitter <= 20 => 4,
        Some(jitter) => {
            notes.push(format!("TCP 抖动偏高 ({jitter}ms)"));
            1
        }
        None => {
            if attempts > 1 {
                notes.push("抖动样本不足".to_owned());
            }
            3
        }
    };
    let stability_score = stability_security_score(stability, &mut notes);

    let mut score = encryption_score
        .saturating_add(transport_score)
        .saturating_add(tls_score)
        .saturating_add(udp_score)
        .saturating_add(cert_score)
        .saturating_add(metadata_score)
        .saturating_add(reliability_score)
        .saturating_add(loss_score)
        .saturating_add(jitter_score)
        .saturating_add(stability_score);
    if score > 100 {
        score = 100;
    }

    let security_level = if protocol == "unknown" {
        SecurityLevel::Unknown
    } else if score >= 80 {
        SecurityLevel::High
    } else if score >= 55 {
        SecurityLevel::Medium
    } else {
        SecurityLevel::Low
    };

    SecurityAssessment {
        security_level,
        encryption_level,
        score,
        note: notes.join("；"),
    }
}

fn encryption_strength(
    node: &ProxyNode,
    tls_status: &TlsProbeStatus,
    protocol: &str,
    notes: &mut Vec<String>,
) -> (EncryptionLevel, u8) {
    if protocol == "http" {
        notes.push("HTTP 为明文传输".to_owned());
        return (EncryptionLevel::Plaintext, 0);
    }

    if protocol == "ss" {
        if let Some(cipher) = node.cipher.as_deref() {
            let cipher_l = cipher.to_ascii_lowercase();
            if is_strong_cipher(&cipher_l) {
                return (EncryptionLevel::Strong, 40);
            }
            if is_weak_cipher(&cipher_l) {
                notes.push(format!("SS 使用弱加密算法 {cipher}"));
                return (EncryptionLevel::Weak, 12);
            }
            notes.push(format!("SS 使用中等强度算法 {cipher}"));
            return (EncryptionLevel::Moderate, 26);
        }

        notes.push("SS 未提供 cipher 信息".to_owned());
        return (EncryptionLevel::Unknown, 18);
    }

    if matches!(
        protocol,
        "trojan" | "https" | "tuic" | "hysteria" | "hysteria2"
    ) {
        return (EncryptionLevel::Strong, 40);
    }

    if matches!(protocol, "vmess" | "vless") {
        if node.tls == Some(true) || tls_status.is_passed() {
            return (EncryptionLevel::Strong, 35);
        }
        notes.push("VMess/VLESS 未确认 TLS/REALITY".to_owned());
        return (EncryptionLevel::Moderate, 24);
    }

    if matches!(protocol, "socks" | "socks5") {
        notes.push("SOCKS5 默认不加密，依赖外层隧道".to_owned());
        return (EncryptionLevel::Weak, 10);
    }

    (EncryptionLevel::Unknown, 16)
}

fn protocol_security_score(protocol: &str) -> u8 {
    match protocol {
        "trojan" | "tuic" | "hysteria" | "hysteria2" | "https" => 20,
        "vless" | "vmess" => 16,
        "ss" => 12,
        "socks" | "socks5" => 6,
        "http" => 0,
        _ => 8,
    }
}

fn tls_security_score(tls_status: &TlsProbeStatus, protocol: &str, notes: &mut Vec<String>) -> u8 {
    match tls_status {
        TlsProbeStatus::Passed => 20,
        TlsProbeStatus::Failed(reason) => {
            if should_probe_tls(protocol) {
                notes.push(format!("TLS 预检失败：{reason}"));
            }
            2
        }
        TlsProbeStatus::Disabled => {
            if should_probe_tls(protocol) {
                notes.push("TLS 检测被关闭".to_owned());
            }
            8
        }
        TlsProbeStatus::Skipped(reason) => {
            if should_probe_tls(protocol) {
                notes.push(format!("TLS 跳过：{reason}"));
                8
            } else {
                12
            }
        }
    }
}

fn udp_security_score(udp_status: &UdpProbeStatus, protocol: &str, notes: &mut Vec<String>) -> u8 {
    if !should_probe_udp(protocol) {
        return 4;
    }

    match udp_status {
        UdpProbeStatus::Passed(_) => 8,
        UdpProbeStatus::Partial(reason) => {
            notes.push(format!("UDP 部分通过：{reason}"));
            4
        }
        UdpProbeStatus::Failed(reason) => {
            notes.push(format!("UDP 失败：{reason}"));
            if is_udp_required_protocol(protocol) {
                0
            } else {
                2
            }
        }
        UdpProbeStatus::Skipped(reason) => {
            notes.push(format!("UDP 跳过：{reason}"));
            if is_udp_required_protocol(protocol) {
                1
            } else {
                4
            }
        }
    }
}

fn stability_security_score(stability: &StabilityMetrics, notes: &mut Vec<String>) -> u8 {
    match stability.level {
        StabilityLevel::Disabled => 6,
        StabilityLevel::High => 10,
        StabilityLevel::Medium => {
            notes.push(format!(
                "稳定性中等：超时率 {:.1}%，最大连续失败 {}",
                stability.timeout_rate_percent, stability.max_consecutive_failures
            ));
            6
        }
        StabilityLevel::Low => {
            notes.push(format!(
                "稳定性较差：超时率 {:.1}%，最大连续失败 {}",
                stability.timeout_rate_percent, stability.max_consecutive_failures
            ));
            1
        }
    }
}

fn cert_validation_score(skip_cert_verify: Option<bool>, notes: &mut Vec<String>) -> u8 {
    match skip_cert_verify {
        Some(true) => {
            notes.push("已配置跳过证书校验".to_owned());
            0
        }
        Some(false) => 10,
        None => {
            notes.push("证书校验策略未知".to_owned());
            6
        }
    }
}

fn metadata_security_score(node: &ProxyNode, protocol: &str, notes: &mut Vec<String>) -> u8 {
    let mut score = 0_u8;

    if let Some(network) = node.network.as_deref() {
        let network_l = network.to_ascii_lowercase();
        if matches!(network_l.as_str(), "grpc" | "ws" | "h2" | "http") {
            notes.push(format!("传输层: {network}"));
            score = score.saturating_add(2);
        }
    }

    if should_probe_tls(protocol) {
        if node.server_name.is_some() {
            score = score.saturating_add(3);
        } else {
            notes.push("TLS 类节点未发现 SNI/ServerName".to_owned());
        }
    }

    score
}

fn is_strong_cipher(cipher: &str) -> bool {
    let strong = [
        "aes-256-gcm",
        "aes-128-gcm",
        "chacha20-ietf-poly1305",
        "xchacha20-ietf-poly1305",
        "2022-blake3-aes-256-gcm",
        "2022-blake3-chacha20-poly1305",
    ];
    strong.iter().any(|item| cipher.contains(item))
}

fn is_weak_cipher(cipher: &str) -> bool {
    let weak = ["rc4", "des", "none", "md5", "bf-cfb"];
    weak.iter().any(|item| cipher.contains(item))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn computes_jitter_and_loss() {
        let latencies = vec![10_u128, 14_u128, 11_u128, 17_u128];
        assert_eq!(jitter(&latencies), Some(4));
        assert_eq!(loss_percent(3, 5), 40.0);
    }

    #[test]
    fn classifies_stability_level() {
        assert_eq!(classify_stability_level(0.0, 0), StabilityLevel::High);
        assert_eq!(classify_stability_level(12.0, 2), StabilityLevel::Medium);
        assert_eq!(classify_stability_level(35.0, 4), StabilityLevel::Low);
    }

    #[test]
    fn udp_required_protocols() {
        assert!(is_udp_required_protocol("tuic"));
        assert!(is_udp_required_protocol("hysteria2"));
        assert!(!is_udp_required_protocol("trojan"));
    }
}
