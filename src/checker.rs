use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
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
        EndpointProbeResult::DnsFailed(reason) => dns_failed(node, reason, options.attempts),
        EndpointProbeResult::Probed {
            resolved_ip_count,
            tcp_probe,
            tls_probe,
        } => build_result(
            node,
            resolved_ip_count,
            tcp_probe,
            tls_probe,
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

    EndpointProbeResult::Probed {
        resolved_ip_count,
        tcp_probe,
        tls_probe,
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
    let security = assess_security(&node, &tls_probe.status, tcp_probe.successes, attempts);

    NodeCheckResult {
        node,
        status,
        dns_ok: true,
        tcp_successes: tcp_probe.successes,
        tcp_attempts: attempts as usize,
        tcp_avg_latency_ms,
        tls_status: tls_probe.status,
        tls_latency_ms: tls_probe.latency_ms,
        security,
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

fn assess_security(
    node: &ProxyNode,
    tls_status: &TlsProbeStatus,
    tcp_successes: usize,
    attempts: u8,
) -> SecurityAssessment {
    let protocol = node.node_type.to_ascii_lowercase();
    let mut notes = Vec::new();

    let (encryption_level, encryption_score) =
        encryption_strength(node, tls_status, &protocol, &mut notes);
    let transport_score = protocol_security_score(&protocol);
    let tls_score = tls_security_score(tls_status, &protocol, &mut notes);
    let cert_score = cert_validation_score(node.skip_cert_verify, &mut notes);
    let metadata_score = metadata_security_score(node, &protocol, &mut notes);
    let reliability_score = if attempts == 0 {
        0
    } else {
        ((tcp_successes as f32 / attempts as f32) * 10.0).round() as u8
    };

    let mut score = encryption_score
        .saturating_add(transport_score)
        .saturating_add(tls_score)
        .saturating_add(cert_score)
        .saturating_add(metadata_score)
        .saturating_add(reliability_score);
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
