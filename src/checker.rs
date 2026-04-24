use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use md5::{Digest, Md5};
use ring::aead::{Aad, AES_128_GCM, LessSafeKey, Nonce, UnboundKey};
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, Error as RustlsError, SignatureScheme,
    StreamOwned,
};

use crate::subscription::{
    inspect_subscription_config, parse_subscription, ProxyNode, SubscriptionConfigHints,
    SubscriptionContentKind,
};

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

#[derive(Clone, Debug)]
pub struct SubscriptionPrivacyAssessment {
    pub level: SecurityLevel,
    pub reason: String,
}

impl Default for SubscriptionPrivacyAssessment {
    fn default() -> Self {
        Self {
            level: SecurityLevel::Unknown,
            reason: "等待下载订阅后评估本机私流安全。".to_owned(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct StartSummary {
    pub total: usize,
    pub unique_endpoints: usize,
    pub duplicate_endpoints: usize,
    pub duplicate_names: usize,
    pub tls_target_count: usize,
    pub local_privacy: SubscriptionPrivacyAssessment,
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
    pub security_reason: String,
    pub encryption_reason: String,
    pub gfw_level: SecurityLevel,
    pub gfw_score: u8,
    pub gfw_reason: String,
    pub anti_tracking_level: SecurityLevel,
    pub anti_tracking_reason: String,
    pub local_network_level: SecurityLevel,
    pub local_network_score: u8,
    pub local_network_reason: String,
    pub live_network_level: SecurityLevel,
    pub live_network_reason: String,
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

    let config_hints = inspect_subscription_config(&content);
    let nodes = parse_subscription(&content)?;
    let summary = summarize_subscription(&nodes, &config_hints);
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
            socket_addrs,
            tcp_probe,
            tls_probe,
            udp_probe,
            stability,
        } => build_result(
            node,
            resolved_ip_count,
            &socket_addrs,
            tcp_probe,
            tls_probe,
            udp_probe,
            stability,
            options.timeout,
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
        socket_addrs: Vec<SocketAddr>,
        tcp_probe: TcpProbe,
        tls_probe: TlsProbeStatusWithLatency,
        udp_probe: UdpProbeStatusWithLatency,
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
    let stability = run_stability_probe(
        &socket_addrs,
        options.timeout,
        options.stability_window_secs,
    );

    EndpointProbeResult::Probed {
        resolved_ip_count,
        socket_addrs,
        tcp_probe,
        tls_probe,
        udp_probe,
        stability,
    }
}

fn summarize_subscription(
    nodes: &[ProxyNode],
    config_hints: &SubscriptionConfigHints,
) -> StartSummary {
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
    let local_privacy = assess_subscription_local_privacy(config_hints, nodes);

    StartSummary {
        total: nodes.len(),
        unique_endpoints,
        duplicate_endpoints,
        duplicate_names,
        tls_target_count,
        local_privacy,
    }
}

fn assess_subscription_local_privacy(
    config_hints: &SubscriptionConfigHints,
    nodes: &[ProxyNode],
) -> SubscriptionPrivacyAssessment {
    if nodes.is_empty() {
        return SubscriptionPrivacyAssessment {
            level: SecurityLevel::Unknown,
            reason: "订阅中没有可评估节点，无法判断本机私流风险。".to_owned(),
        };
    }

    let mut notes = Vec::new();
    let mut score = 100_i32;

    match config_hints.kind {
        SubscriptionContentKind::ClashYaml => {
            match config_hints.dns_enabled {
                Some(true) => {
                    if config_hints.dns_nameserver_count == 0 {
                        score -= 20;
                        push_note(&mut notes, "已启用 DNS 模块，但未见上游 nameserver 配置");
                    }
                    if config_hints.dns_fallback_count == 0 {
                        score -= 5;
                        push_note(&mut notes, "DNS 未配置 fallback，上游容灾与泄露回退保护较弱");
                    }
                    if !config_hints
                        .dns_enhanced_mode
                        .as_deref()
                        .is_some_and(|value| {
                            matches!(value.to_ascii_lowercase().as_str(), "fake-ip" | "redir-host")
                        })
                    {
                        score -= 10;
                        push_note(&mut notes, "DNS 未启用 fake-ip/redir-host 增强模式");
                    }
                    if config_hints.dns_respect_rules != Some(true) {
                        score -= 5;
                        push_note(&mut notes, "DNS 未明确 respect-rules，分流一致性未知");
                    }
                    if config_hints.allow_lan == Some(true)
                        && config_hints
                            .dns_listen
                            .as_deref()
                            .is_some_and(|listener| !is_local_listener(listener))
                    {
                        score -= 10;
                        push_note(&mut notes, "DNS 监听地址对局域网开放，可能扩大本地查询暴露面");
                    }
                }
                Some(false) => {
                    score -= 30;
                    push_note(&mut notes, "订阅显式关闭 DNS 模块，本机查询是否经代理无法保证");
                }
                None => {
                    score -= 25;
                    push_note(&mut notes, "未见完整 DNS 保护配置，存在 DNS 泄露不确定性");
                }
            }

            match config_hints.mode.as_deref().map(|value| value.to_ascii_lowercase()) {
                Some(mode) if mode == "rule" => {
                    if config_hints.rule_count + config_hints.rule_provider_count == 0 {
                        score -= 20;
                        push_note(&mut notes, "mode=rule 但未见 rules/rule-providers，私流分流规则不足");
                    }
                }
                Some(mode) if mode == "direct" => {
                    score -= 35;
                    push_note(&mut notes, "mode=direct 会让系统流量默认直连，本机私流泄露风险高");
                }
                Some(mode) if mode == "global" => {
                    push_note(&mut notes, "mode=global 更依赖客户端是否正确接管系统流量");
                }
                _ => {
                    if config_hints.rule_count + config_hints.rule_provider_count == 0 {
                        score -= 15;
                        push_note(&mut notes, "未见明确路由模式与规则集，难以确认私网/域名请求不会旁路");
                    }
                }
            }

            match config_hints.tun_enabled {
                Some(true) => {
                    if config_hints.tun_auto_route != Some(true) {
                        score -= 5;
                        push_note(&mut notes, "已启用 TUN，但未明确 auto-route，系统级接管能力存疑");
                    }
                    if config_hints.tun_strict_route != Some(true) {
                        score -= 3;
                        push_note(&mut notes, "已启用 TUN，但未开启 strict-route，旁路流量保护较弱");
                    }
                    if config_hints.tun_dns_hijack_count == 0 {
                        score -= 5;
                        push_note(&mut notes, "已启用 TUN，但未见 dns-hijack，系统 DNS 接管不完整");
                    }
                }
                Some(false) | None => {
                    score -= 10;
                    push_note(&mut notes, "未启用 TUN，本机全部应用流量是否接管取决于外部客户端设置");
                }
            }

            if config_hints.allow_lan == Some(true) && has_local_proxy_listener(config_hints) {
                score -= 25;
                push_note(&mut notes, "allow-lan 已开启，本机代理端口可能暴露给局域网设备");
            }
            if config_hints.allow_lan == Some(true)
                && config_hints
                    .bind_address
                    .as_deref()
                    .is_some_and(|address| !is_local_listener(address))
            {
                score -= 10;
                push_note(&mut notes, "bind-address 并非本地回环地址，局域网访问暴露面更大");
            }

            if let Some(controller) = config_hints.external_controller.as_deref() {
                if !config_hints.secret_present {
                    score -= 25;
                    push_note(
                        &mut notes,
                        format!("external-controller {controller} 已开启但未配置 secret"),
                    );
                } else if !is_local_listener(controller) {
                    score -= 10;
                    push_note(
                        &mut notes,
                        format!("external-controller {controller} 建议仅绑定本地地址"),
                    );
                }
            }

            if notes.is_empty() {
                push_note(
                    &mut notes,
                    "订阅包含 DNS、规则与 TUN 等私流保护配置，泄露风险相对较低",
                );
            }
        }
        SubscriptionContentKind::ProxyList | SubscriptionContentKind::Unknown => {
            let total = nodes.len() as f32;
            let weak_transport_count = nodes
                .iter()
                .filter(|node| node_uses_weak_private_transport(node))
                .count();
            let insecure_cert_count = nodes
                .iter()
                .filter(|node| node.skip_cert_verify == Some(true))
                .count();
            let tls_like_ratio = nodes
                .iter()
                .filter(|node| node_uses_tls_like_private_transport(node))
                .count() as f32
                / total;

            score = 60;
            push_note(
                &mut notes,
                "订阅仅包含节点列表，未提供 DNS/规则/TUN 配置，无法实测本机 DNS/私网流量是否泄露",
            );

            if weak_transport_count > 0 {
                score -= 20;
                push_note(
                    &mut notes,
                    format!("发现 {weak_transport_count} 个明文/弱隧道节点，私流经其转发时风险较高"),
                );
            }
            if insecure_cert_count > 0 {
                score -= 15;
                push_note(
                    &mut notes,
                    format!("发现 {insecure_cert_count} 个节点跳过证书校验，中间人风险较高"),
                );
            }
            if weak_transport_count == 0 && insecure_cert_count == 0 && tls_like_ratio >= 0.8 {
                score += 10;
                push_note(&mut notes, "多数节点具备 TLS/REALITY/QUIC 类外层保护");
            }
        }
    }

    let level = security_level_from_score(score);
    let reason = format!(
        "{}；当前为订阅配置/节点特征的启发式评估，未执行真实 DNS 泄露或私网流量抓包。",
        join_notes(&notes)
    );

    SubscriptionPrivacyAssessment { level, reason }
}

fn security_level_from_score(score: i32) -> SecurityLevel {
    match score.clamp(0, 100) {
        80..=100 => SecurityLevel::High,
        55..=79 => SecurityLevel::Medium,
        0..=54 => SecurityLevel::Low,
        _ => SecurityLevel::Unknown,
    }
}

fn has_local_proxy_listener(config_hints: &SubscriptionConfigHints) -> bool {
    config_hints.mixed_port.is_some()
        || config_hints.http_port.is_some()
        || config_hints.socks_port.is_some()
        || config_hints.redir_port.is_some()
        || config_hints.tproxy_port.is_some()
}

fn is_local_listener(listener: &str) -> bool {
    let lower = listener.trim().to_ascii_lowercase();
    lower.starts_with("127.")
        || lower.starts_with("localhost")
        || lower.starts_with("::1")
        || lower.starts_with("[::1]")
}

fn node_uses_weak_private_transport(node: &ProxyNode) -> bool {
    let protocol = node.node_type.to_ascii_lowercase();
    if matches!(protocol.as_str(), "http" | "socks" | "socks5") {
        return true;
    }

    node.cipher.as_deref().is_some_and(|cipher| {
        is_weak_cipher(&cipher.to_ascii_lowercase())
    })
}

fn node_uses_tls_like_private_transport(node: &ProxyNode) -> bool {
    let protocol = node.node_type.to_ascii_lowercase();
    node.tls == Some(true)
        || matches!(
            protocol.as_str(),
            "trojan" | "https" | "tuic" | "hysteria" | "hysteria2"
        )
        || node.security.as_deref().is_some_and(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "tls" | "xtls" | "reality"
            )
        })
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
            security_reason: "无法评估：DNS失败".to_owned(),
            encryption_reason: "无法判断加密方式：DNS失败".to_owned(),
            gfw_level: SecurityLevel::Unknown,
            gfw_score: 0,
            gfw_reason: "无法评估 GFW 通过性：DNS失败".to_owned(),
            anti_tracking_level: SecurityLevel::Unknown,
            anti_tracking_reason: "无法评估防追踪：DNS失败".to_owned(),
            local_network_level: SecurityLevel::Unknown,
            local_network_score: 0,
            local_network_reason: "无法评估本地网络可达性：DNS失败".to_owned(),
            live_network_level: SecurityLevel::Unknown,
            live_network_reason: "无法评估现网稳定性：DNS失败".to_owned(),
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

fn ordered_socket_addrs(
    socket_addrs: &[SocketAddr],
    prefer_addr: Option<SocketAddr>,
) -> Vec<SocketAddr> {
    let mut ordered_addrs = Vec::with_capacity(socket_addrs.len());
    if let Some(addr) = prefer_addr {
        ordered_addrs.push(addr);
    }
    for addr in socket_addrs {
        if Some(*addr) != prefer_addr {
            ordered_addrs.push(*addr);
        }
    }
    ordered_addrs
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

    let ordered_addrs = ordered_socket_addrs(socket_addrs, prefer_addr);

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

const PROBE_TARGET_HOST: &str = "www.example.com";
const PROBE_TARGET_PORT: u16 = 80;

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

    let ordered_addrs = ordered_socket_addrs(socket_addrs, prefer_addr);

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
    prefer_addr: Option<SocketAddr>,
) -> TtfbProbeStatusWithLatency {
    match node.node_type.to_ascii_lowercase().as_str() {
        "trojan" => {
            return run_trojan_proxy_ttfb(node, socket_addrs, timeout, tls_probe, prefer_addr)
        }
        "vless" => {
            return run_vless_proxy_ttfb(node, socket_addrs, timeout, tls_probe, prefer_addr)
        }
        _ => {}
    }

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
    for addr in ordered_socket_addrs(socket_addrs, prefer_addr) {
        match http_first_byte_probe(&addr, &node.server, timeout) {
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

fn run_trojan_proxy_ttfb(
    node: &ProxyNode,
    socket_addrs: &[SocketAddr],
    timeout: Duration,
    tls_probe: &TlsProbeStatusWithLatency,
    prefer_addr: Option<SocketAddr>,
) -> TtfbProbeStatusWithLatency {
    let Some(password) = node.password.as_deref() else {
        return TtfbProbeStatusWithLatency {
            status: TtfbProbeStatus::Failed("缺少 password".to_owned()),
            latency_ms: None,
        };
    };

    if !matches!(tls_probe.status, TlsProbeStatus::Passed) {
        return TtfbProbeStatusWithLatency {
            status: TtfbProbeStatus::Failed("Trojan 代理链TTFB依赖 TLS 通过".to_owned()),
            latency_ms: None,
        };
    }

    let mut payload = Vec::new();
    payload.extend_from_slice(hex_sha224(password).as_bytes());
    payload.extend_from_slice(b"\r\n");
    payload.extend_from_slice(&build_trojan_connect_request(PROBE_TARGET_HOST, PROBE_TARGET_PORT));
    payload.extend_from_slice(&build_proxy_http_request(PROBE_TARGET_HOST));

    let mut last_error = String::new();
    for socket_addr in ordered_socket_addrs(socket_addrs, prefer_addr) {
        let started_at = Instant::now();
        match tls_connect(node, &socket_addr, timeout) {
            Ok(mut stream) => {
                match read_first_byte_after_payload(
                    &mut stream,
                    &payload,
                    "Trojan代理链HTTP首包",
                    started_at,
                ) {
                    Ok(latency_ms) => {
                        return TtfbProbeStatusWithLatency {
                            status: TtfbProbeStatus::Passed("Trojan代理链HTTP首包".to_owned()),
                            latency_ms: Some(latency_ms),
                        }
                    }
                    Err(error) => last_error = error,
                }
            }
            Err(error) => last_error = error,
        }
    }

    TtfbProbeStatusWithLatency {
        status: TtfbProbeStatus::Failed(if last_error.is_empty() {
            "Trojan代理链TTFB失败".to_owned()
        } else {
            last_error
        }),
        latency_ms: None,
    }
}

fn run_vless_proxy_ttfb(
    node: &ProxyNode,
    socket_addrs: &[SocketAddr],
    timeout: Duration,
    tls_probe: &TlsProbeStatusWithLatency,
    prefer_addr: Option<SocketAddr>,
) -> TtfbProbeStatusWithLatency {
    if uses_reality_mode(node) {
        return reality_ttfb_status(node);
    }

    let Some(uuid) = node.uuid.as_deref() else {
        return TtfbProbeStatusWithLatency {
            status: TtfbProbeStatus::Failed("缺少 uuid/id".to_owned()),
            latency_ms: None,
        };
    };

    let uuid_bytes = match parse_uuid_bytes(uuid) {
        Some(bytes) => bytes,
        None => {
            return TtfbProbeStatusWithLatency {
                status: TtfbProbeStatus::Failed("uuid/id 格式无效".to_owned()),
                latency_ms: None,
            }
        }
    };

    let require_tls = vless_requires_tls(node);
    if require_tls && !matches!(tls_probe.status, TlsProbeStatus::Passed) {
        return TtfbProbeStatusWithLatency {
            status: TtfbProbeStatus::Failed("VLESS 代理链TTFB依赖 TLS/REALITY 前置通过".to_owned()),
            latency_ms: None,
        };
    }

    let mut payload = build_vless_request(&uuid_bytes, PROBE_TARGET_HOST, PROBE_TARGET_PORT);
    payload.extend_from_slice(&build_proxy_http_request(PROBE_TARGET_HOST));

    let mut last_error = String::new();
    for socket_addr in ordered_socket_addrs(socket_addrs, prefer_addr) {
        let started_at = Instant::now();
        if require_tls {
            match tls_connect(node, &socket_addr, timeout) {
                Ok(mut stream) => {
                    match read_first_byte_after_payload(
                        &mut stream,
                        &payload,
                        "VLESS代理链HTTP首包",
                        started_at,
                    ) {
                        Ok(latency_ms) => {
                            return TtfbProbeStatusWithLatency {
                                status: TtfbProbeStatus::Passed("VLESS代理链HTTP首包".to_owned()),
                                latency_ms: Some(latency_ms),
                            }
                        }
                        Err(error) => last_error = error,
                    }
                }
                Err(error) => last_error = error,
            }
        } else {
            match TcpStream::connect_timeout(&socket_addr, timeout) {
                Ok(mut stream) => {
                    let _ = stream.set_read_timeout(Some(timeout));
                    let _ = stream.set_write_timeout(Some(timeout));
                    match read_first_byte_after_payload(
                        &mut stream,
                        &payload,
                        "VLESS代理链HTTP首包",
                        started_at,
                    ) {
                        Ok(latency_ms) => {
                            return TtfbProbeStatusWithLatency {
                                status: TtfbProbeStatus::Passed("VLESS代理链HTTP首包".to_owned()),
                                latency_ms: Some(latency_ms),
                            }
                        }
                        Err(error) => last_error = error,
                    }
                }
                Err(error) => last_error = format!("VLESS TCP 连接失败: {error}"),
            }
        }
    }

    TtfbProbeStatusWithLatency {
        status: TtfbProbeStatus::Failed(if last_error.is_empty() {
            "VLESS代理链TTFB失败".to_owned()
        } else {
            last_error
        }),
        latency_ms: None,
    }
}

fn build_proxy_http_request(host: &str) -> Vec<u8> {
    format!("HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").into_bytes()
}

fn read_first_byte_after_payload<T: Read + Write>(
    stream: &mut T,
    payload: &[u8],
    label: &str,
    started_at: Instant,
) -> Result<u128, String> {
    stream
        .write_all(payload)
        .map_err(|error| format!("{label}发送请求失败: {error}"))?;
    stream
        .flush()
        .map_err(|error| format!("{label}刷新请求失败: {error}"))?;

    let mut first_byte = [0_u8; 1];
    stream
        .read_exact(&mut first_byte)
        .map_err(|error| format!("{label}读取首包失败: {error}"))?;
    Ok(started_at.elapsed().as_millis())
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
    socket_addrs: &[SocketAddr],
    tcp_probe: TcpProbe,
    tls_probe: TlsProbeStatusWithLatency,
    udp_probe: UdpProbeStatusWithLatency,
    stability: StabilityMetrics,
    timeout: Duration,
    attempts: u8,
) -> NodeCheckResult {
    let tcp_avg_latency_ms = average(&tcp_probe.latencies_ms);
    let tcp_jitter_ms = jitter(&tcp_probe.latencies_ms);
    let tcp_loss_percent = loss_percent(tcp_probe.successes, attempts as usize);
    let ttfb_probe = run_ttfb_probe(
        &node,
        socket_addrs,
        &tls_probe,
        timeout,
        tcp_probe.success_addr,
    );
    let tcp_ok = tcp_probe.successes > 0;
    let protocol_probe = run_protocol_probe(
        &node,
        socket_addrs,
        timeout,
        &tls_probe.status,
        tcp_probe.successes,
        attempts,
        tcp_probe.success_addr,
    );
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
        &ttfb_probe.status,
        ttfb_probe.latency_ms,
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

#[derive(Debug)]
struct InsecureTlsVerifier;

impl ServerCertVerifier for InsecureTlsVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

fn tls_connect(
    node: &ProxyNode,
    socket_addr: &SocketAddr,
    timeout: Duration,
) -> Result<StreamOwned<ClientConnection, TcpStream>, String> {
    let mut tcp_stream =
        TcpStream::connect_timeout(socket_addr, timeout).map_err(|error| error.to_string())?;
    let _ = tcp_stream.set_read_timeout(Some(timeout));
    let _ = tcp_stream.set_write_timeout(Some(timeout));

    let server_name = resolve_server_name(node).map_err(|error| error.to_string())?;
    let tls_config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(InsecureTlsVerifier))
        .with_no_client_auth();
    let mut connection = ClientConnection::new(Arc::new(tls_config), server_name)
        .map_err(|error| error.to_string())?;

    while connection.is_handshaking() {
        connection
            .complete_io(&mut tcp_stream)
            .map_err(|error| format!("TLS握手失败: {error}"))?;
    }

    Ok(StreamOwned::new(connection, tcp_stream))
}

fn resolve_server_name(node: &ProxyNode) -> Result<ServerName<'static>, &'static str> {
    if let Some(server_name) = node.server_name.as_deref() {
        return ServerName::try_from(server_name.to_owned()).map_err(|_| "无效的 SNI/ServerName");
    }

    if let Ok(ip) = node.server.parse::<IpAddr>() {
        return Ok(ServerName::IpAddress(ip.into()));
    }

    ServerName::try_from(node.server.to_owned()).map_err(|_| "无效的 server 域名")
}

fn run_trojan_real_probe(
    node: &ProxyNode,
    socket_addrs: &[SocketAddr],
    timeout: Duration,
    tls_status: &TlsProbeStatus,
) -> ProtocolProbeStatus {
    let Some(password) = node.password.as_deref() else {
        return ProtocolProbeStatus::Failed("缺少 password".to_owned());
    };

    if !matches!(tls_status, TlsProbeStatus::Passed) {
        return ProtocolProbeStatus::Partial("需要TLS通过".to_owned());
    }

    let mut payload = Vec::new();
    payload.extend_from_slice(hex_sha224(password).as_bytes());
    payload.extend_from_slice(b"\r\n");
    payload.extend_from_slice(&build_trojan_connect_request(PROBE_TARGET_HOST, PROBE_TARGET_PORT));

    let mut last_error = String::new();
    for socket_addr in socket_addrs {
        let mut tls_stream = match tls_connect(node, socket_addr, timeout) {
            Ok(stream) => stream,
            Err(error) => {
                last_error = error;
                continue;
            }
        };

        if let Err(error) = tls_stream.write_all(&payload) {
            last_error = format!("发送Trojan认证失败: {error}");
            continue;
        }
        if let Err(error) = tls_stream.flush() {
            last_error = format!("刷新Trojan认证失败: {error}");
            continue;
        }

        let mut one_byte = [0_u8; 1];
        match tls_stream.read(&mut one_byte) {
            Ok(0) => {
                last_error = "认证后连接被关闭".to_owned();
            }
            Ok(_) => {
                return ProtocolProbeStatus::Passed("Trojan真实握手成功(收到响应)".to_owned());
            }
            Err(error) if matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
                return ProtocolProbeStatus::Passed(
                    "Trojan真实握手成功(写入后连接保持)".to_owned(),
                );
            }
            Err(error) => {
                last_error = format!("Trojan读取响应失败: {error}");
            }
        }
    }

    ProtocolProbeStatus::Failed(if last_error.is_empty() {
        "Trojan真实握手失败".to_owned()
    } else {
        last_error
    })
}

fn run_vless_real_probe(
    node: &ProxyNode,
    socket_addrs: &[SocketAddr],
    timeout: Duration,
    tls_status: &TlsProbeStatus,
) -> ProtocolProbeStatus {
    if uses_reality_mode(node) {
        return reality_protocol_probe_status(node);
    }

    let Some(uuid) = node.uuid.as_deref() else {
        return ProtocolProbeStatus::Failed("缺少 uuid/id".to_owned());
    };

    let uuid_bytes = match parse_uuid_bytes(uuid) {
        Some(bytes) => bytes,
        None => return ProtocolProbeStatus::Failed("uuid/id 格式无效".to_owned()),
    };

    let require_tls = vless_requires_tls(node);
    if require_tls && !matches!(tls_status, TlsProbeStatus::Passed) {
        return ProtocolProbeStatus::Partial("TLS/REALITY要求未满足".to_owned());
    }

    let request = build_vless_request(&uuid_bytes, PROBE_TARGET_HOST, PROBE_TARGET_PORT);
    let mut last_error = String::new();

    for socket_addr in socket_addrs {
        let outcome = if require_tls {
            match tls_connect(node, socket_addr, timeout) {
                Ok(mut stream) => send_and_expect_open(&mut stream, &request, "VLESS"),
                Err(error) => Err(error),
            }
        } else {
            match TcpStream::connect_timeout(socket_addr, timeout) {
                Ok(mut stream) => {
                    let _ = stream.set_read_timeout(Some(timeout));
                    let _ = stream.set_write_timeout(Some(timeout));
                    send_and_expect_open(&mut stream, &request, "VLESS")
                }
                Err(error) => Err(error.to_string()),
            }
        };

        match outcome {
            Ok(message) => return ProtocolProbeStatus::Passed(message),
            Err(error) => last_error = error,
        }
    }

    ProtocolProbeStatus::Failed(if last_error.is_empty() {
        "VLESS真实握手失败".to_owned()
    } else {
        last_error
    })
}

fn run_vmess_probe(
    node: &ProxyNode,
    socket_addrs: &[SocketAddr],
    timeout: Duration,
    tls_status: &TlsProbeStatus,
) -> ProtocolProbeStatus {
    if node.uuid.is_none() {
        return ProtocolProbeStatus::Failed("缺少 uuid/id".to_owned());
    }

    if node.tls == Some(true) && !matches!(tls_status, TlsProbeStatus::Passed) {
        return ProtocolProbeStatus::Partial("TLS要求未满足".to_owned());
    }

    let network = node
        .network
        .as_deref()
        .map(|value| value.trim().to_ascii_lowercase())
        .unwrap_or_else(|| "tcp".to_owned());
    if !matches!(network.as_str(), "tcp" | "") {
        return ProtocolProbeStatus::Partial(format!(
            "当前仅实现 VMess TCP AEAD 真实握手，暂不支持 {} 传输",
            if network.is_empty() { "默认" } else { network.as_str() }
        ));
    }

    let cipher_method = match vmess_request_cipher_method(node) {
        Ok(method) => method,
        Err(error) => return ProtocolProbeStatus::Partial(error),
    };

    let request = match build_vmess_aead_request(node, PROBE_TARGET_HOST, PROBE_TARGET_PORT, cipher_method) {
        Ok(request) => request,
        Err(error) => return ProtocolProbeStatus::Failed(error),
    };

    let mut last_error = String::new();
    for socket_addr in socket_addrs {
        let outcome = if node.tls == Some(true) {
            match tls_connect(node, socket_addr, timeout) {
                Ok(mut stream) => send_and_expect_open(&mut stream, &request, "VMess AEAD"),
                Err(error) => Err(error),
            }
        } else {
            match TcpStream::connect_timeout(socket_addr, timeout) {
                Ok(mut stream) => {
                    let _ = stream.set_read_timeout(Some(timeout));
                    let _ = stream.set_write_timeout(Some(timeout));
                    send_and_expect_open(&mut stream, &request, "VMess AEAD")
                }
                Err(error) => Err(error.to_string()),
            }
        };

        match outcome {
            Ok(message) => return ProtocolProbeStatus::Passed(message),
            Err(error) => last_error = error,
        }
    }

    ProtocolProbeStatus::Failed(if last_error.is_empty() {
        "VMess AEAD 真实握手失败".to_owned()
    } else {
        last_error
    })
}

fn run_hysteria2_auth_probe(node: &ProxyNode, timeout: Duration) -> ProtocolProbeStatus {
    let Some(auth) = node.password.as_deref().filter(|value| !value.trim().is_empty()) else {
        return ProtocolProbeStatus::Failed("缺少 Hysteria2 auth/password".to_owned());
    };

    let server_name = node
        .server_name
        .clone()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| node.server.clone());
    let config = hysteria2::config::Config {
        auth: auth.to_owned(),
        server_addr: format!("{}:{}", node.server, node.port),
        server_name,
        insecure: node.skip_cert_verify.unwrap_or(false),
        port_hopping_range: None,
    };

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            return ProtocolProbeStatus::Failed(format!("创建 Hysteria2 运行时失败: {error}"));
        }
    };

    let outcome = runtime.block_on(async {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let client = hysteria2::connect(&config)
            .await
            .map_err(|error| format!("Hysteria2 认证失败: {error}"))?;
        let mut stream = client
            .tcp_connect(format!("{}:{}", PROBE_TARGET_HOST, PROBE_TARGET_PORT))
            .await
            .map_err(|error| format!("Hysteria2 打开代理 TCP 失败: {error}"))?;

        stream
            .write_all(&build_proxy_http_request(PROBE_TARGET_HOST))
            .await
            .map_err(|error| format!("Hysteria2 发送代理请求失败: {error}"))?;
        stream
            .flush()
            .await
            .map_err(|error| format!("Hysteria2 刷新代理请求失败: {error}"))?;

        let mut one_byte = [0_u8; 1];
        match tokio::time::timeout(timeout, stream.read(&mut one_byte)).await {
            Ok(Ok(0)) => Err("Hysteria2 认证后连接被关闭".to_owned()),
            Ok(Ok(_)) => Ok("Hysteria2 应用层认证成功(收到响应)".to_owned()),
            Ok(Err(error)) => Err(format!("Hysteria2 读取响应失败: {error}")),
            Err(_) => Ok("Hysteria2 应用层认证成功(写入后连接保持)".to_owned()),
        }
    });

    match outcome {
        Ok(message) => ProtocolProbeStatus::Passed(message),
        Err(error) => ProtocolProbeStatus::Failed(error),
    }
}

fn run_tuic_auth_probe(
    node: &ProxyNode,
    socket_addrs: &[SocketAddr],
    timeout: Duration,
    prefer_addr: Option<SocketAddr>,
) -> ProtocolProbeStatus {
    let Some(uuid) = node.uuid.as_deref() else {
        return ProtocolProbeStatus::Failed("缺少 uuid/id".to_owned());
    };
    let Some(password) = node.password.as_deref().filter(|value| !value.trim().is_empty()) else {
        return ProtocolProbeStatus::Failed("缺少 password".to_owned());
    };
    let uuid_bytes = match parse_uuid_bytes(uuid) {
        Some(bytes) => bytes,
        None => return ProtocolProbeStatus::Failed("uuid/id 格式无效".to_owned()),
    };
    let server_name = match quic_server_name(node) {
        Ok(value) => value,
        Err(error) => return ProtocolProbeStatus::Failed(error),
    };
    let alpn_candidates = quic_alpn_candidates(node);
    if alpn_candidates.is_empty() {
        return ProtocolProbeStatus::Failed("缺少可用 ALPN".to_owned());
    }

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            return ProtocolProbeStatus::Failed(format!("创建 TUIC 运行时失败: {error}"));
        }
    };

    let ordered_addrs = ordered_socket_addrs(socket_addrs, prefer_addr);
    let mut last_error = String::new();
    for alpn in alpn_candidates {
        for socket_addr in &ordered_addrs {
            match runtime.block_on(run_tuic_auth_probe_once(
                node,
                *socket_addr,
                &server_name,
                &alpn,
                timeout,
                &uuid_bytes,
                password.as_bytes(),
            )) {
                Ok(message) => return ProtocolProbeStatus::Passed(format!("{message}(ALPN {alpn})")),
                Err(error) => last_error = format!("ALPN {alpn}: {error}"),
            }
        }
    }

    ProtocolProbeStatus::Failed(if last_error.is_empty() {
        "TUIC 应用层认证失败".to_owned()
    } else {
        last_error
    })
}

async fn run_tuic_auth_probe_once(
    node: &ProxyNode,
    socket_addr: SocketAddr,
    server_name: &str,
    alpn: &str,
    timeout: Duration,
    uuid: &[u8; 16],
    password: &[u8],
) -> Result<String, String> {
    let (_endpoint, connection) = connect_quic_session(node, socket_addr, server_name, alpn, timeout)
        .await?;

    let mut token = [0_u8; 32];
    connection
        .export_keying_material(&mut token, uuid, password)
        .map_err(|error| format!("导出 TUIC 认证材料失败: {error:?}"))?;

    let mut auth_stream = connection
        .open_uni()
        .await
        .map_err(|error| format!("打开 TUIC 认证流失败: {error}"))?;
    auth_stream
        .write_all(&build_tuic_auth_command(uuid, &token))
        .await
        .map_err(|error| format!("发送 TUIC 认证命令失败: {error}"))?;
    auth_stream
        .finish()
        .map_err(|error| format!("结束 TUIC 认证流失败: {error}"))?;

    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|error| format!("打开 TUIC TCP 中继流失败: {error}"))?;
    let connect_request = build_tuic_connect_request(PROBE_TARGET_HOST, PROBE_TARGET_PORT)?;
    send.write_all(&connect_request)
        .await
        .map_err(|error| format!("发送 TUIC Connect 命令失败: {error}"))?;
    send.write_all(&build_proxy_http_request(PROBE_TARGET_HOST))
        .await
        .map_err(|error| format!("发送 TUIC 代理请求失败: {error}"))?;
    send.finish()
        .map_err(|error| format!("结束 TUIC 代理写入失败: {error}"))?;

    let mut one_byte = [0_u8; 1];
    let result = match tokio::time::timeout(timeout, recv.read(&mut one_byte)).await {
        Ok(Ok(Some(_))) => Ok("TUIC 应用层认证成功(收到响应)".to_owned()),
        Ok(Ok(None)) => Err("TUIC 认证后连接被关闭".to_owned()),
        Ok(Err(error)) => Err(format!("TUIC 读取响应失败: {error}")),
        Err(_) => Ok("TUIC 应用层认证成功(写入后连接保持)".to_owned()),
    };
    connection.close(0u32.into(), b"probe");
    result
}

fn build_tuic_auth_command(uuid: &[u8; 16], token: &[u8; 32]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(2 + 16 + 32);
    payload.push(0x05);
    payload.push(0x00);
    payload.extend_from_slice(uuid);
    payload.extend_from_slice(token);
    payload
}

fn build_tuic_connect_request(target_host: &str, target_port: u16) -> Result<Vec<u8>, String> {
    let mut payload = Vec::with_capacity(2 + target_host.len() + 4);
    payload.push(0x05);
    payload.push(0x01);
    payload.extend_from_slice(&build_tuic_address(target_host, target_port)?);
    Ok(payload)
}

fn build_tuic_address(target_host: &str, target_port: u16) -> Result<Vec<u8>, String> {
    if let Ok(ipv4) = target_host.parse::<Ipv4Addr>() {
        let mut encoded = Vec::with_capacity(1 + 4 + 2);
        encoded.push(0x01);
        encoded.extend_from_slice(&ipv4.octets());
        encoded.extend_from_slice(&target_port.to_be_bytes());
        return Ok(encoded);
    }

    if let Ok(ipv6) = target_host.parse::<Ipv6Addr>() {
        let mut encoded = Vec::with_capacity(1 + 16 + 2);
        encoded.push(0x02);
        encoded.extend_from_slice(&ipv6.octets());
        encoded.extend_from_slice(&target_port.to_be_bytes());
        return Ok(encoded);
    }

    let host = target_host.as_bytes();
    if host.len() > u8::MAX as usize {
        return Err("TUIC 目标域名过长".to_owned());
    }

    let mut encoded = Vec::with_capacity(1 + 1 + host.len() + 2);
    encoded.push(0x00);
    encoded.push(host.len() as u8);
    encoded.extend_from_slice(host);
    encoded.extend_from_slice(&target_port.to_be_bytes());
    Ok(encoded)
}

fn vmess_request_cipher_method(node: &ProxyNode) -> Result<u8, String> {
    let cipher = node
        .cipher
        .as_deref()
        .map(|value| value.trim().to_ascii_lowercase())
        .unwrap_or_else(|| "auto".to_owned());
    match cipher.as_str() {
        "" | "auto" | "chacha20-poly1305" | "chacha20-ietf-poly1305" => Ok(0x04),
        "aes-128-gcm" => Ok(0x03),
        "none" => Ok(0x05),
        other => Err(format!("当前未实现 VMess 数据加密算法 {other} 的 AEAD 握手")),
    }
}

fn build_vmess_aead_request(
    node: &ProxyNode,
    target_host: &str,
    target_port: u16,
    cipher_method: u8,
) -> Result<Vec<u8>, String> {
    let uuid = node.uuid.as_deref().ok_or_else(|| "缺少 uuid/id".to_owned())?;
    let uuid_bytes = parse_uuid_bytes(uuid).ok_or_else(|| "uuid/id 格式无效".to_owned())?;
    let instruction_key = vmess_instruction_key(&uuid_bytes);

    let random = SystemRandom::new();
    let auth_id = vmess_auth_id(&instruction_key, &random)?;

    let mut nonce = [0_u8; 8];
    random
        .fill(&mut nonce)
        .map_err(|_| "生成 VMess AEAD nonce 失败".to_owned())?;

    let mut header = Vec::with_capacity(64);
    header.push(0x01);

    let mut request_iv = [0_u8; 16];
    random
        .fill(&mut request_iv)
        .map_err(|_| "生成 VMess Request IV 失败".to_owned())?;
    header.extend_from_slice(&request_iv);

    let mut request_key = [0_u8; 16];
    random
        .fill(&mut request_key)
        .map_err(|_| "生成 VMess Request Key 失败".to_owned())?;
    header.extend_from_slice(&request_key);

    let mut response_auth_v = [0_u8; 1];
    random
        .fill(&mut response_auth_v)
        .map_err(|_| "生成 VMess Response Auth V 失败".to_owned())?;
    header.push(response_auth_v[0]);

    header.push(0x01);
    header.push(cipher_method);
    header.push(0x00);
    header.push(0x01);
    header.extend_from_slice(&target_port.to_be_bytes());

    if let Ok(ipv4) = target_host.parse::<Ipv4Addr>() {
        header.push(0x01);
        header.extend_from_slice(&ipv4.octets());
    } else if let Ok(ipv6) = target_host.parse::<Ipv6Addr>() {
        header.push(0x03);
        header.extend_from_slice(&ipv6.octets());
    } else {
        let host = target_host.as_bytes();
        if host.len() > u8::MAX as usize {
            return Err("VMess 目标域名过长".to_owned());
        }
        header.push(0x02);
        header.push(host.len() as u8);
        header.extend_from_slice(host);
    }

    let checksum = vmess_fnv1a(&header).to_be_bytes();
    header.extend_from_slice(&checksum);

    let encrypted_length = vmess_encrypt_aead_length(&instruction_key, &auth_id, &nonce, header.len() as u16)?;
    let encrypted_header = vmess_encrypt_aead_header(&instruction_key, &auth_id, &nonce, &header)?;

    let mut request = Vec::with_capacity(16 + encrypted_length.len() + nonce.len() + encrypted_header.len());
    request.extend_from_slice(&auth_id);
    request.extend_from_slice(&encrypted_length);
    request.extend_from_slice(&nonce);
    request.extend_from_slice(&encrypted_header);
    Ok(request)
}

fn vmess_instruction_key(uuid: &[u8; 16]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(uuid);
    hasher.update(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    let digest = hasher.finalize();
    let mut key = [0_u8; 16];
    key.copy_from_slice(&digest[..16]);
    key
}

fn vmess_auth_id(instruction_key: &[u8; 16], random: &SystemRandom) -> Result<[u8; 16], String> {
    let mut plain = [0_u8; 16];
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    plain[..8].copy_from_slice(&now.to_be_bytes());
    random
        .fill(&mut plain[8..12])
        .map_err(|_| "生成 VMess Auth ID 随机段失败".to_owned())?;
    let checksum = crc32fast::hash(&plain[..12]).to_be_bytes();
    plain[12..16].copy_from_slice(&checksum);

    let auth_key = vmess_kdf(instruction_key, &[b"AES Auth ID Encryption"]);
    let cipher = Aes128::new_from_slice(&auth_key[..16])
        .map_err(|_| "构建 VMess Auth ID 密钥失败".to_owned())?;
    let mut block = aes::cipher::generic_array::GenericArray::clone_from_slice(&plain);
    cipher.encrypt_block(&mut block);
    Ok(block.into())
}

fn vmess_encrypt_aead_length(
    instruction_key: &[u8; 16],
    auth_id: &[u8; 16],
    nonce: &[u8; 8],
    header_len: u16,
) -> Result<Vec<u8>, String> {
    let key = vmess_kdf(
        instruction_key,
        &[b"VMess Header AEAD Key_Length", auth_id, nonce],
    );
    let nonce_bytes = vmess_kdf(
        instruction_key,
        &[b"VMess Header AEAD Nonce_Length", auth_id, nonce],
    );
    vmess_seal_aes128_gcm(
        &key[..16],
        &nonce_bytes[..12],
        auth_id,
        &header_len.to_be_bytes(),
    )
}

fn vmess_encrypt_aead_header(
    instruction_key: &[u8; 16],
    auth_id: &[u8; 16],
    nonce: &[u8; 8],
    header: &[u8],
) -> Result<Vec<u8>, String> {
    let key = vmess_kdf(instruction_key, &[b"VMess Header AEAD Key", auth_id, nonce]);
    let nonce_bytes = vmess_kdf(
        instruction_key,
        &[b"VMess Header AEAD Nonce", auth_id, nonce],
    );
    vmess_seal_aes128_gcm(&key[..16], &nonce_bytes[..12], auth_id, header)
}

fn vmess_seal_aes128_gcm(
    key_bytes: &[u8],
    nonce_bytes: &[u8],
    aad_bytes: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    let unbound_key = UnboundKey::new(&AES_128_GCM, key_bytes)
        .map_err(|_| "构建 VMess AES-128-GCM 密钥失败".to_owned())?;
    let key = LessSafeKey::new(unbound_key);
    let nonce = Nonce::try_assume_unique_for_key(nonce_bytes)
        .map_err(|_| "构建 VMess AEAD nonce 失败".to_owned())?;
    let mut output = plaintext.to_vec();
    key.seal_in_place_append_tag(nonce, Aad::from(aad_bytes), &mut output)
        .map_err(|_| "VMess AEAD 加密失败".to_owned())?;
    Ok(output)
}

fn vmess_kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let mut current_key = b"VMess AEAD KDF".to_vec();
    for path_item in path {
        current_key = vmess_hmac_sha256(&current_key, path_item).to_vec();
    }
    vmess_hmac_sha256(&current_key, key)
}

fn vmess_hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let signing_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&signing_key, data);
    let mut output = [0_u8; 32];
    output.copy_from_slice(tag.as_ref());
    output
}

fn vmess_fnv1a(data: &[u8]) -> u32 {
    let mut hash = 0x811c9dc5_u32;
    for byte in data {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

fn vless_requires_tls(node: &ProxyNode) -> bool {
    if node.tls == Some(true) {
        return true;
    }
    if let Some(security) = node.security.as_deref() {
        return matches!(
            security.to_ascii_lowercase().as_str(),
            "tls" | "xtls" | "reality"
        );
    }
    false
}

fn reality_protocol_probe_status(node: &ProxyNode) -> ProtocolProbeStatus {
    if let Some(message) = reality_config_error(node) {
        return ProtocolProbeStatus::Failed(message);
    }

    let mode = if node
        .security
        .as_deref()
        .is_some_and(|value| value.eq_ignore_ascii_case("reality"))
    {
        "REALITY"
    } else {
        "XTLS Vision/REALITY"
    };

    ProtocolProbeStatus::Skipped(format!(
        "{} 参数已识别，但当前未实现 Xray/sing-box 级专用客户端握手，已避免误判为普通 TLS 成功",
        mode
    ))
}

fn reality_ttfb_status(node: &ProxyNode) -> TtfbProbeStatusWithLatency {
    let status = if let Some(message) = reality_config_error(node) {
        TtfbProbeStatus::Failed(message)
    } else {
        TtfbProbeStatus::Skipped(
            "REALITY/XTLS Vision 代理链 TTFB 需专用客户端，当前不再复用普通 TLS 基线"
                .to_owned(),
        )
    };

    TtfbProbeStatusWithLatency {
        status,
        latency_ms: None,
    }
}

fn reality_config_error(node: &ProxyNode) -> Option<String> {
    let mut missing = Vec::new();

    if node
        .client_fingerprint
        .as_deref()
        .is_none_or(|value| value.trim().is_empty())
    {
        missing.push("client-fingerprint/fp");
    }

    let is_reality = node
        .security
        .as_deref()
        .is_some_and(|value| value.eq_ignore_ascii_case("reality"));
    if is_reality {
        if node
            .reality_public_key
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
        {
            missing.push("public-key/pbk");
        }
        if node
            .reality_short_id
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
        {
            missing.push("short-id/sid");
        }
    }

    if missing.is_empty() {
        None
    } else {
        Some(format!("REALITY 参数不完整，缺少 {}", missing.join("、")))
    }
}

fn send_and_expect_open<T: Read + Write>(
    stream: &mut T,
    payload: &[u8],
    protocol: &str,
) -> Result<String, String> {
    stream
        .write_all(payload)
        .map_err(|error| format!("{protocol}发送请求失败: {error}"))?;
    stream
        .flush()
        .map_err(|error| format!("{protocol}刷新请求失败: {error}"))?;

    let mut one_byte = [0_u8; 1];
    match stream.read(&mut one_byte) {
        Ok(0) => Err(format!("{protocol}请求后连接被关闭")),
        Ok(_) => Ok(format!("{protocol}真实握手成功(收到响应)")),
        Err(error) if matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
            Ok(format!("{protocol}真实握手成功(写入后连接保持)"))
        }
        Err(error) => Err(format!("{protocol}读取响应失败: {error}")),
    }
}

fn build_trojan_connect_request(target_host: &str, target_port: u16) -> Vec<u8> {
    let mut request = Vec::with_capacity(32);
    let host = target_host.as_bytes();
    request.push(0x01);
    request.push(0x03);
    request.push(host.len() as u8);
    request.extend_from_slice(host);
    request.extend_from_slice(&target_port.to_be_bytes());
    request.extend_from_slice(b"\r\n");
    request
}

fn build_vless_request(uuid: &[u8; 16], target_host: &str, target_port: u16) -> Vec<u8> {
    let mut request = Vec::with_capacity(64);
    let host = target_host.as_bytes();
    request.push(0x00);
    request.extend_from_slice(uuid);
    request.push(0x00);
    request.push(0x01);
    request.extend_from_slice(&target_port.to_be_bytes());
    request.push(0x02);
    request.push(host.len() as u8);
    request.extend_from_slice(host);
    request
}

fn parse_uuid_bytes(input: &str) -> Option<[u8; 16]> {
    let compact = input.chars().filter(|ch| *ch != '-').collect::<String>();
    if compact.len() != 32 {
        return None;
    }

    let mut output = [0_u8; 16];
    for (index, chunk_start) in (0..32).step_by(2).enumerate() {
        let chunk = &compact[chunk_start..chunk_start + 2];
        output[index] = u8::from_str_radix(chunk, 16).ok()?;
    }
    Some(output)
}

fn hex_sha224(input: &str) -> String {
    let digest = sha224(input.as_bytes());
    bytes_to_hex(&digest)
}

fn sha224(input: &[u8]) -> [u8; 28] {
    const H0: [u32; 8] = [
        0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7,
        0xbefa4fa4,
    ];
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut state = H0;
    let padded = sha256_pad(input);

    for chunk in padded.chunks_exact(64) {
        let mut w = [0_u32; 64];
        for (index, block) in chunk.chunks_exact(4).enumerate().take(16) {
            w[index] = u32::from_be_bytes([block[0], block[1], block[2], block[3]]);
        }
        for index in 16..64 {
            let s0 = w[index - 15].rotate_right(7)
                ^ w[index - 15].rotate_right(18)
                ^ (w[index - 15] >> 3);
            let s1 = w[index - 2].rotate_right(17)
                ^ w[index - 2].rotate_right(19)
                ^ (w[index - 2] >> 10);
            w[index] = w[index - 16]
                .wrapping_add(s0)
                .wrapping_add(w[index - 7])
                .wrapping_add(s1);
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[index])
                .wrapping_add(w[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    let mut output = [0_u8; 28];
    for (index, word) in state.iter().take(7).enumerate() {
        output[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    output
}

fn sha256_pad(input: &[u8]) -> Vec<u8> {
    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity(input.len() + 72);
    padded.extend_from_slice(input);
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    padded
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(nibble_to_hex(byte >> 4));
        output.push(nibble_to_hex(byte & 0x0F));
    }
    output
}

fn nibble_to_hex(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'a' + (nibble - 10)) as char,
        _ => '0',
    }
}

fn run_protocol_probe(
    node: &ProxyNode,
    socket_addrs: &[SocketAddr],
    timeout: Duration,
    tls_status: &TlsProbeStatus,
    tcp_successes: usize,
    attempts: u8,
    prefer_addr: Option<SocketAddr>,
) -> ProtocolProbeStatus {
    let protocol = node.node_type.to_ascii_lowercase();

    if tcp_successes == 0 {
        return ProtocolProbeStatus::Failed("TCP不可达".to_owned());
    }

    if tcp_successes < attempts as usize {
        return ProtocolProbeStatus::Partial("TCP采样未全通过".to_owned());
    }

    match protocol.as_str() {
        "trojan" => run_trojan_real_probe(node, socket_addrs, timeout, tls_status),
        "vless" => run_vless_real_probe(node, socket_addrs, timeout, tls_status),
        "vmess" => run_vmess_probe(node, socket_addrs, timeout, tls_status),
        "tuic" => {
            if node.uuid.is_none() || node.password.is_none() {
                ProtocolProbeStatus::Failed("缺少 uuid/password".to_owned())
            } else if node.udp == Some(false) {
                ProtocolProbeStatus::Failed("UDP被禁用".to_owned())
            } else {
                run_tuic_auth_probe(node, socket_addrs, timeout, prefer_addr)
            }
        }
        "hysteria2" => {
            if node.password.is_none() {
                ProtocolProbeStatus::Failed("缺少认证字段".to_owned())
            } else if node.udp == Some(false) {
                ProtocolProbeStatus::Failed("UDP被禁用".to_owned())
            } else {
                run_hysteria2_auth_probe(node, timeout)
            }
        }
        "hysteria" => {
            if node.password.is_none() && node.uuid.is_none() {
                ProtocolProbeStatus::Failed("缺少认证字段".to_owned())
            } else if node.udp == Some(false) {
                ProtocolProbeStatus::Failed("UDP被禁用".to_owned())
            } else {
                match run_quic_transport_probe(node, socket_addrs, timeout, prefer_addr) {
                    Ok(message) => ProtocolProbeStatus::Partial(format!(
                        "{message}；Hysteria v1 应用层认证仍依赖自定义客户端协议栈，当前先保留为传输层通过"
                    )),
                    Err(error) => ProtocolProbeStatus::Partial(format!("QUIC传输未建立：{error}")),
                }
            }
        }
        _ => ProtocolProbeStatus::Skipped("该协议未配置握手探测".to_owned()),
    }
}

fn run_quic_transport_probe(
    node: &ProxyNode,
    socket_addrs: &[SocketAddr],
    timeout: Duration,
    prefer_addr: Option<SocketAddr>,
) -> Result<String, String> {
    let server_name = quic_server_name(node)?;
    let alpn_candidates = quic_alpn_candidates(node);
    if alpn_candidates.is_empty() {
        return Err("缺少可用 ALPN".to_owned());
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("创建 QUIC 运行时失败: {error}"))?;

    let ordered_addrs = ordered_socket_addrs(socket_addrs, prefer_addr);
    let mut last_error = String::new();
    for alpn in alpn_candidates {
        for socket_addr in &ordered_addrs {
            match runtime.block_on(connect_quic_transport(
                node,
                *socket_addr,
                &server_name,
                &alpn,
                timeout,
            )) {
                Ok(()) => return Ok(format!("QUIC握手成功(ALPN {alpn})")),
                Err(error) => last_error = format!("ALPN {alpn}: {error}"),
            }
        }
    }

    Err(if last_error.is_empty() {
        "QUIC握手失败".to_owned()
    } else {
        last_error
    })
}

async fn connect_quic_transport(
    node: &ProxyNode,
    socket_addr: SocketAddr,
    server_name: &str,
    alpn: &str,
    timeout: Duration,
) -> Result<(), String> {
    let (_endpoint, connection) = connect_quic_session(node, socket_addr, server_name, alpn, timeout)
        .await?;
    connection.close(0u32.into(), b"probe");
    Ok(())
}

async fn connect_quic_session(
    node: &ProxyNode,
    socket_addr: SocketAddr,
    server_name: &str,
    alpn: &str,
    timeout: Duration,
) -> Result<(quinn::Endpoint, quinn::Connection), String> {
    let bind_addr = if socket_addr.is_ipv4() {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    };

    let mut endpoint = quinn::Endpoint::client(bind_addr)
        .map_err(|error| format!("绑定 QUIC 端点失败: {error}"))?;
    endpoint.set_default_client_config(build_quic_client_config(node, alpn)?);

    let connecting = endpoint
        .connect(socket_addr, server_name)
        .map_err(|error| format!("创建 QUIC 连接失败: {error}"))?;
    let connection = tokio::time::timeout(timeout, connecting)
        .await
        .map_err(|_| format!("QUIC握手超时({}ms)", timeout.as_millis()))?
        .map_err(|error| format!("QUIC握手失败: {error}"))?;
    Ok((endpoint, connection))
}

fn build_quic_client_config(node: &ProxyNode, alpn: &str) -> Result<quinn::ClientConfig, String> {
    let mut tls_config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(InsecureTlsVerifier))
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![alpn.as_bytes().to_vec()];
    if node.skip_cert_verify == Some(false) {
        tls_config.enable_sni = true;
    }

    let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
        .map_err(|error| format!("构建 QUIC TLS 配置失败: {error}"))?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_config));
    client_config.transport_config(Arc::new(quinn::TransportConfig::default()));
    Ok(client_config)
}

fn quic_server_name(node: &ProxyNode) -> Result<String, String> {
    if let Some(server_name) = node.server_name.as_deref() {
        if !server_name.trim().is_empty() {
            return Ok(server_name.trim().to_owned());
        }
    }

    if node.server.parse::<IpAddr>().is_ok() {
        return Err("缺少 SNI/ServerName".to_owned());
    }

    Ok(node.server.trim().to_owned())
}

fn quic_alpn_candidates(node: &ProxyNode) -> Vec<String> {
    let mut values = Vec::new();
    if let Some(alpn) = node.alpn.as_deref() {
        for part in alpn.split(',') {
            let trimmed = part.trim();
            if !trimmed.is_empty() && !values.iter().any(|item| item == trimmed) {
                values.push(trimmed.to_owned());
            }
        }
    }

    if values.is_empty() {
        match node.node_type.to_ascii_lowercase().as_str() {
            "tuic" | "hysteria2" => values.push("h3".to_owned()),
            "hysteria" => {
                values.push("hysteria".to_owned());
                values.push("h3".to_owned());
            }
            _ => {}
        }
    }

    values
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
    ttfb_status: &TtfbProbeStatus,
    ttfb_ms: Option<u128>,
    tcp_success_rate: f32,
    tcp_loss_percent: f32,
    tcp_jitter_ms: Option<u128>,
    stability: &StabilityMetrics,
    attempts: u8,
) -> SecurityAssessment {
    let protocol = node.node_type.to_ascii_lowercase();
    let mut encryption_notes = Vec::new();
    let mut security_notes = Vec::new();

    let (encryption_level, encryption_score) =
        encryption_strength(node, tls_status, &protocol, &mut encryption_notes);
    let transport_score = protocol_security_score(&protocol);
    let tls_score = tls_security_score(tls_status, &protocol, &mut security_notes);
    let udp_score = udp_security_score(udp_status, &protocol, &mut security_notes);
    let cert_score = cert_validation_score(node.skip_cert_verify, &mut security_notes);
    let metadata_score = metadata_security_score(node, &protocol, &mut security_notes);
    let reliability_score = (tcp_success_rate.clamp(0.0, 1.0) * 10.0).round() as u8;
    let loss_score = if tcp_loss_percent <= 5.0 {
        6
    } else if tcp_loss_percent <= 15.0 {
        4
    } else {
        push_note(
            &mut security_notes,
            format!("TCP 丢包偏高 ({tcp_loss_percent:.1}%)"),
        );
        1
    };
    let jitter_score = match tcp_jitter_ms {
        Some(jitter) if jitter <= 8 => 6,
        Some(jitter) if jitter <= 20 => 4,
        Some(jitter) => {
            push_note(&mut security_notes, format!("TCP 抖动偏高 ({jitter}ms)"));
            1
        }
        None => {
            if attempts > 1 {
                push_note(&mut security_notes, "抖动样本不足");
            }
            3
        }
    };
    let stability_score = stability_security_score(stability, &mut security_notes);
    let (gfw_level, gfw_score, gfw_reason) = assess_gfw_profile(node, &protocol, tls_status);
    let (anti_tracking_level, anti_tracking_reason) =
        assess_anti_tracking_profile(node, &protocol, tls_status, &encryption_level);
    let (local_network_level, local_network_score, local_network_reason) =
        assess_local_network_profile(
            &protocol,
            udp_status,
            ttfb_status,
            ttfb_ms,
            tcp_success_rate,
            tcp_loss_percent,
            tcp_jitter_ms,
            stability,
            attempts,
        );
    let (live_network_level, live_network_reason) = assess_live_network_profile(
        stability,
        ttfb_status,
        ttfb_ms,
        tcp_loss_percent,
        tcp_jitter_ms,
        &gfw_level,
        &anti_tracking_level,
    );

    let mut base_score = encryption_score
        .saturating_add(transport_score)
        .saturating_add(tls_score)
        .saturating_add(udp_score)
        .saturating_add(cert_score)
        .saturating_add(metadata_score)
        .saturating_add(reliability_score)
        .saturating_add(loss_score)
        .saturating_add(jitter_score)
        .saturating_add(stability_score);
    if base_score > 100 {
        base_score = 100;
    }

    let score = (((u16::from(base_score) * 70)
        + (u16::from(gfw_score) * 15)
        + (u16::from(local_network_score) * 15))
        / 100) as u8;

    let security_level = if protocol == "unknown" {
        SecurityLevel::Unknown
    } else if score >= 80 {
        SecurityLevel::High
    } else if score >= 55 {
        SecurityLevel::Medium
    } else {
        SecurityLevel::Low
    };

    let encryption_reason = join_notes(&encryption_notes);
    let security_reason = join_notes(&[
        protocol_security_baseline_reason(node, &protocol, tls_status),
        format!("GFW 通过性 {} 分：{}", gfw_score, gfw_reason),
        format!(
            "本地网络可达性 {} 分：{}",
            local_network_score, local_network_reason
        ),
        anti_tracking_reason.clone(),
        live_network_reason.clone(),
    ]);
    let mut notes = Vec::new();
    append_notes(&mut notes, &encryption_notes);
    append_notes(&mut notes, &security_notes);
    push_note(&mut notes, format!("GFW通过性评估：{} 分，{}", gfw_score, gfw_reason));
    push_note(&mut notes, format!("防追踪评估：{}", anti_tracking_reason));
    push_note(
        &mut notes,
        format!(
            "本地网络可达性评估：{} 分，{}",
            local_network_score, local_network_reason
        ),
    );
    push_note(&mut notes, format!("现网稳定性：{}", live_network_reason));

    SecurityAssessment {
        security_level,
        encryption_level,
        score,
        security_reason,
        encryption_reason,
        gfw_level,
        gfw_score,
        gfw_reason,
        anti_tracking_level,
        anti_tracking_reason,
        local_network_level,
        local_network_score,
        local_network_reason,
        live_network_level,
        live_network_reason,
        note: notes.join("；"),
    }
}

fn push_note(notes: &mut Vec<String>, note: impl Into<String>) {
    let note = note.into();
    if note.is_empty() || notes.iter().any(|item| item == &note) {
        return;
    }
    notes.push(note);
}

fn append_notes(target: &mut Vec<String>, source: &[String]) {
    for note in source {
        push_note(target, note.clone());
    }
}

fn join_notes(notes: &[String]) -> String {
    notes
        .iter()
        .filter(|item| !item.is_empty())
        .cloned()
        .collect::<Vec<_>>()
        .join("；")
}

fn protocol_security_baseline_reason(
    node: &ProxyNode,
    protocol: &str,
    tls_status: &TlsProbeStatus,
) -> String {
    let protocol_name = protocol_label(protocol);
    if protocol == "http" {
        return "HTTP 明文直连，协议安全基线最低".to_owned();
    }

    if matches!(protocol, "socks" | "socks5") {
        return "SOCKS5 只做转发，安全性依赖外层隧道".to_owned();
    }

    if protocol == "ss" {
        return node
            .cipher
            .as_deref()
            .filter(|value| !value.is_empty())
            .map(|cipher| format!("Shadowsocks 依赖 {cipher} 算法保护链路"))
            .unwrap_or_else(|| "Shadowsocks 缺少 cipher 信息，安全性判断不完整".to_owned());
    }

    if uses_reality_mode(node) {
        return format!("{protocol_name} 使用 REALITY/XTLS Vision，协议伪装基线较高");
    }

    if protocol_uses_tls_like_transport(node, protocol, tls_status) {
        return format!("{protocol_name} 使用 TLS 类外层封装，协议安全基线较高");
    }

    format!("{protocol_name} 仍以协议层封装为主，外层伪装较弱")
}

fn assess_gfw_profile(
    node: &ProxyNode,
    protocol: &str,
    tls_status: &TlsProbeStatus,
) -> (SecurityLevel, u8, String) {
    let protocol_name = protocol_label(protocol);
    let uses_tls_like = protocol_uses_tls_like_transport(node, protocol, tls_status);
    let has_sni = has_named_value(node.server_name.as_deref());
    let has_alpn = has_named_value(node.alpn.as_deref());
    let http_cover = has_http_cover_transport(node);
    let reality_mode = uses_reality_mode(node);

    if protocol == "http" || matches!(protocol, "socks" | "socks5") {
        return (
            SecurityLevel::Low,
            28,
            format!("{protocol_name} 缺少 TLS/REALITY 外层伪装，GFW 通过性偏低"),
        );
    }

    if reality_mode {
        return (
            SecurityLevel::High,
            95,
            "使用 REALITY/XTLS Vision，链路外观更接近真实站点请求".to_owned(),
        );
    }

    if matches!(protocol, "trojan" | "https") && uses_tls_like && has_sni {
        return (
            SecurityLevel::High,
            88,
            "使用 TLS + SNI，外观接近常见 HTTPS 流量".to_owned(),
        );
    }

    if uses_tls_like && has_sni && http_cover {
        return (
            SecurityLevel::High,
            84,
            format!(
                "使用 TLS + SNI + {} 传输伪装，更接近常见 Web 流量",
                node.network.as_deref().unwrap_or("Web 类")
            ),
        );
    }

    if matches!(protocol, "tuic" | "hysteria" | "hysteria2") {
        if has_alpn {
            return (
                SecurityLevel::Medium,
                62,
                format!("{protocol_name} 走 QUIC/UDP，开放网络下通常较稳，但对 UDP/QUIC 策略更敏感"),
            );
        }
        return (
            SecurityLevel::Low,
            34,
            format!("{protocol_name} 走 QUIC/UDP，但缺少 ALPN/SNI 等伪装字段，GFW 风险较高"),
        );
    }

    if uses_tls_like && (has_sni || http_cover) {
        return (
            SecurityLevel::Medium,
            60,
            "具备 TLS 外层，但伪装字段不够完整，GFW 通过性中等".to_owned(),
        );
    }

    (
        SecurityLevel::Low,
        30,
        format!("{protocol_name} 缺少 TLS/REALITY/SNI 等关键信号，GFW 通过性偏弱"),
    )
}

fn assess_local_network_profile(
    protocol: &str,
    udp_status: &UdpProbeStatus,
    ttfb_status: &TtfbProbeStatus,
    ttfb_ms: Option<u128>,
    tcp_success_rate: f32,
    tcp_loss_percent: f32,
    tcp_jitter_ms: Option<u128>,
    stability: &StabilityMetrics,
    attempts: u8,
) -> (SecurityLevel, u8, String) {
    let mut score = (tcp_success_rate.clamp(0.0, 1.0) * 40.0).round() as i32;

    score += if tcp_loss_percent <= 5.0 {
        20
    } else if tcp_loss_percent <= 15.0 {
        12
    } else {
        4
    };

    score += match tcp_jitter_ms {
        Some(jitter) if jitter <= 8 => 10,
        Some(jitter) if jitter <= 20 => 6,
        Some(_) => 2,
        None if attempts > 1 => 4,
        None => 6,
    };

    score += match ttfb_status {
        TtfbProbeStatus::Passed(_) => match ttfb_ms {
            Some(value) if value <= 350 => 15,
            Some(value) if value <= 800 => 10,
            Some(_) => 6,
            None => 8,
        },
        TtfbProbeStatus::Failed(_) => 1,
        TtfbProbeStatus::Skipped(_) => 5,
    };

    let udp_required = is_udp_required_protocol(protocol);
    score += match udp_status {
        UdpProbeStatus::Passed(_) => {
            if udp_required {
                10
            } else {
                6
            }
        }
        UdpProbeStatus::Partial(_) => {
            if udp_required {
                5
            } else {
                4
            }
        }
        UdpProbeStatus::Failed(_) => {
            if udp_required {
                0
            } else {
                2
            }
        }
        UdpProbeStatus::Skipped(_) => {
            if udp_required {
                2
            } else {
                4
            }
        }
    };

    score += match stability.level {
        StabilityLevel::High => 15,
        StabilityLevel::Medium => 10,
        StabilityLevel::Low => 4,
        StabilityLevel::Disabled => 6,
    };

    let score = score.clamp(0, 100) as u8;
    let level = if score >= 80 {
        SecurityLevel::High
    } else if score >= 55 {
        SecurityLevel::Medium
    } else {
        SecurityLevel::Low
    };

    let jitter_desc = tcp_jitter_ms
        .map(|value| format!("抖动 {value}ms"))
        .unwrap_or_else(|| {
            if attempts > 1 {
                "抖动样本不足".to_owned()
            } else {
                "单次采样无抖动统计".to_owned()
            }
        });
    let ttfb_desc = match ttfb_status {
        TtfbProbeStatus::Passed(_) => ttfb_ms
            .map(|value| format!("TTFB {value}ms"))
            .unwrap_or_else(|| "TTFB 通过".to_owned()),
        TtfbProbeStatus::Failed(reason) => format!("TTFB 失败({reason})"),
        TtfbProbeStatus::Skipped(reason) => format!("TTFB 跳过({reason})"),
    };
    let stability_desc = if matches!(stability.level, StabilityLevel::Disabled) {
        "未开启持续稳定性窗口".to_owned()
    } else {
        format!(
            "稳定性 {}（窗口 {} 秒，超时率 {:.1}%）",
            stability.level.label(),
            stability.window_secs,
            stability.timeout_rate_percent
        )
    };

    (
        level,
        score,
        format!(
            "TCP 成功率 {:.0}% 、丢包 {:.1}% 、{}；{}；UDP {}；{}",
            tcp_success_rate * 100.0,
            tcp_loss_percent,
            jitter_desc,
            ttfb_desc,
            udp_status.short_label(),
            stability_desc
        ),
    )
}

fn assess_anti_tracking_profile(
    node: &ProxyNode,
    protocol: &str,
    tls_status: &TlsProbeStatus,
    encryption_level: &EncryptionLevel,
) -> (SecurityLevel, String) {
    let protocol_name = protocol_label(protocol);
    let uses_tls_like = protocol_uses_tls_like_transport(node, protocol, tls_status);
    let has_sni = has_named_value(node.server_name.as_deref());
    let has_alpn = has_named_value(node.alpn.as_deref());
    let http_cover = has_http_cover_transport(node);
    let cert_strict = node.skip_cert_verify != Some(true);
    let reality_mode = uses_reality_mode(node);

    if matches!(encryption_level, EncryptionLevel::Plaintext | EncryptionLevel::Weak) {
        return (
            SecurityLevel::Low,
            "链路加密较弱或明文，容易被侧写与关联识别".to_owned(),
        );
    }

    if !cert_strict {
        return (
            SecurityLevel::Low,
            "已跳过证书校验，指纹可信度不足，防追踪能力较弱".to_owned(),
        );
    }

    if reality_mode || (uses_tls_like && has_sni && has_alpn && (http_cover || has_sni)) {
        return (
            SecurityLevel::High,
            "TLS/REALITY 指纹字段较完整，外观更接近真实业务流量".to_owned(),
        );
    }

    if uses_tls_like && (has_sni || has_alpn) {
        return (
            SecurityLevel::Medium,
            format!("{protocol_name} 具备部分 TLS 指纹字段，但伪装完整性一般"),
        );
    }

    (
        SecurityLevel::Low,
        format!("{protocol_name} 缺少 SNI/ALPN 等指纹补全字段，容易被关联识别"),
    )
}

fn assess_live_network_profile(
    stability: &StabilityMetrics,
    ttfb_status: &TtfbProbeStatus,
    ttfb_ms: Option<u128>,
    tcp_loss_percent: f32,
    tcp_jitter_ms: Option<u128>,
    gfw_level: &SecurityLevel,
    anti_tracking_level: &SecurityLevel,
) -> (SecurityLevel, String) {
    let ttfb_failed = matches!(ttfb_status, TtfbProbeStatus::Failed(_));
    let jitter = tcp_jitter_ms.unwrap_or(0);
    let gfw_low = matches!(gfw_level, SecurityLevel::Low);
    let anti_low = matches!(anti_tracking_level, SecurityLevel::Low);
    let ttfb_desc = match ttfb_status {
        TtfbProbeStatus::Passed(_) => ttfb_ms
            .map(|value| format!("TTFB {value}ms"))
            .unwrap_or_else(|| "TTFB 通过".to_owned()),
        TtfbProbeStatus::Failed(reason) => format!("TTFB 失败({reason})"),
        TtfbProbeStatus::Skipped(reason) => format!("TTFB 跳过({reason})"),
    };

    if matches!(stability.level, StabilityLevel::Disabled) {
        let level = if matches!(ttfb_status, TtfbProbeStatus::Passed(_))
            && tcp_loss_percent <= 5.0
            && tcp_jitter_ms.is_some_and(|value| value <= 15)
            && !gfw_low
            && !anti_low
        {
            SecurityLevel::Medium
        } else {
            SecurityLevel::Low
        };

        return (
            level,
            format!(
                "未开启持续稳定性窗口，按 {}、丢包 {:.1}% 、抖动 {}ms 估计；GFW {}，防追踪 {}",
                ttfb_desc,
                tcp_loss_percent,
                jitter,
                gfw_level.label(),
                anti_tracking_level.label()
            ),
        );
    }

    let level = if matches!(stability.level, StabilityLevel::High)
        && tcp_loss_percent <= 5.0
        && jitter <= 15
        && !ttfb_failed
        && !gfw_low
        && !anti_low
    {
        SecurityLevel::High
    } else if matches!(stability.level, StabilityLevel::Low)
        || tcp_loss_percent > 15.0
        || jitter > 30
        || ttfb_failed
        || (gfw_low && anti_low)
    {
        SecurityLevel::Low
    } else {
        SecurityLevel::Medium
    };

    (
        level,
        format!(
            "窗口 {} 秒内超时率 {:.1}% 、最大连续失败 {}；{}；GFW {}，防追踪 {}",
            stability.window_secs,
            stability.timeout_rate_percent,
            stability.max_consecutive_failures,
            ttfb_desc,
            gfw_level.label(),
            anti_tracking_level.label()
        ),
    )
}

fn protocol_label(protocol: &str) -> String {
    match protocol {
        "ss" => "Shadowsocks".to_owned(),
        "socks" | "socks5" => "SOCKS5".to_owned(),
        "http" => "HTTP".to_owned(),
        other => {
            let mut chars = other.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => "Unknown".to_owned(),
            }
        }
    }
}

fn protocol_uses_tls_like_transport(
    node: &ProxyNode,
    protocol: &str,
    tls_status: &TlsProbeStatus,
) -> bool {
    tls_status.is_passed()
        || node.tls == Some(true)
        || matches!(protocol, "trojan" | "https" | "tuic" | "hysteria" | "hysteria2")
        || node.security.as_deref().is_some_and(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "tls" | "xtls" | "reality"
            )
        })
}

fn uses_reality_mode(node: &ProxyNode) -> bool {
    node.security.as_deref().is_some_and(|value| {
        matches!(value.to_ascii_lowercase().as_str(), "reality" | "xtls")
    }) || node.flow.as_deref().is_some_and(|value| value.to_ascii_lowercase().contains("vision"))
}

fn has_http_cover_transport(node: &ProxyNode) -> bool {
    node.network.as_deref().is_some_and(|value| {
        matches!(
            value.to_ascii_lowercase().as_str(),
            "ws" | "grpc" | "h2" | "http"
        )
    })
}

fn has_named_value(value: Option<&str>) -> bool {
    value.is_some_and(|item| !item.trim().is_empty())
}

fn encryption_strength(
    node: &ProxyNode,
    tls_status: &TlsProbeStatus,
    protocol: &str,
    notes: &mut Vec<String>,
) -> (EncryptionLevel, u8) {
    if protocol == "http" {
        push_note(notes, "HTTP 为明文传输");
        return (EncryptionLevel::Plaintext, 0);
    }

    if protocol == "ss" {
        if let Some(cipher) = node.cipher.as_deref() {
            let cipher_l = cipher.to_ascii_lowercase();
            if is_strong_cipher(&cipher_l) {
                push_note(notes, format!("Shadowsocks 使用 {cipher} 加密"));
                return (EncryptionLevel::Strong, 40);
            }
            if is_weak_cipher(&cipher_l) {
                push_note(notes, format!("Shadowsocks 使用弱加密算法 {cipher}"));
                return (EncryptionLevel::Weak, 12);
            }
            push_note(notes, format!("Shadowsocks 使用中等强度算法 {cipher}"));
            return (EncryptionLevel::Moderate, 26);
        }

        push_note(notes, "Shadowsocks 未提供 cipher 信息");
        return (EncryptionLevel::Unknown, 18);
    }

    if matches!(
        protocol,
        "trojan" | "https" | "tuic" | "hysteria" | "hysteria2"
    ) {
        if matches!(protocol, "tuic" | "hysteria" | "hysteria2") {
            push_note(notes, format!("{} 使用 QUIC/TLS 类加密", protocol_label(protocol)));
        } else {
            push_note(notes, format!("{} 使用 TLS 外层加密", protocol_label(protocol)));
        }
        return (EncryptionLevel::Strong, 40);
    }

    if matches!(protocol, "vmess" | "vless") {
        if node.tls == Some(true) || tls_status.is_passed() {
            let outer = node
                .security
                .as_deref()
                .filter(|value| !value.is_empty())
                .unwrap_or("TLS");
            push_note(
                notes,
                format!("{} 使用 {} 外层加密", protocol_label(protocol), outer),
            );
            return (EncryptionLevel::Strong, 35);
        }
        push_note(notes, "VMess/VLESS 未确认 TLS/REALITY");
        return (EncryptionLevel::Moderate, 24);
    }

    if matches!(protocol, "socks" | "socks5") {
        push_note(notes, "SOCKS5 默认不加密，依赖外层隧道");
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
                push_note(notes, format!("TLS 预检失败：{reason}"));
            }
            2
        }
        TlsProbeStatus::Disabled => {
            if should_probe_tls(protocol) {
                push_note(notes, "TLS 检测被关闭");
            }
            8
        }
        TlsProbeStatus::Skipped(reason) => {
            if should_probe_tls(protocol) {
                push_note(notes, format!("TLS 跳过：{reason}"));
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
            push_note(notes, format!("UDP 部分通过：{reason}"));
            4
        }
        UdpProbeStatus::Failed(reason) => {
            push_note(notes, format!("UDP 失败：{reason}"));
            if is_udp_required_protocol(protocol) {
                0
            } else {
                2
            }
        }
        UdpProbeStatus::Skipped(reason) => {
            push_note(notes, format!("UDP 跳过：{reason}"));
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
            push_note(notes, format!(
                "稳定性中等：超时率 {:.1}%，最大连续失败 {}",
                stability.timeout_rate_percent, stability.max_consecutive_failures
            ));
            6
        }
        StabilityLevel::Low => {
            push_note(notes, format!(
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
            push_note(notes, "已配置跳过证书校验");
            0
        }
        Some(false) => 10,
        None => {
            push_note(notes, "证书校验策略未知");
            6
        }
    }
}

fn metadata_security_score(node: &ProxyNode, protocol: &str, notes: &mut Vec<String>) -> u8 {
    let mut score = 0_u8;

    if let Some(network) = node.network.as_deref() {
        let network_l = network.to_ascii_lowercase();
        if matches!(network_l.as_str(), "grpc" | "ws" | "h2" | "http") {
            push_note(notes, format!("传输层: {network}"));
            score = score.saturating_add(2);
        }
    }

    if should_probe_tls(protocol) {
        if node.server_name.is_some() {
            score = score.saturating_add(3);
        } else {
            push_note(notes, "TLS 类节点未发现 SNI/ServerName");
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

    #[test]
    fn parses_uuid_bytes() {
        let parsed = parse_uuid_bytes("550e8400-e29b-41d4-a716-446655440000").unwrap();
        assert_eq!(
            parsed,
            [
                0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4, 0xa7, 0x16, 0x44, 0x66, 0x55, 0x44,
                0x00, 0x00
            ]
        );
    }

    #[test]
    fn computes_sha224_correctly() {
        assert_eq!(
            hex_sha224("test"),
            "90a3ed9e32b2aaf4c61c410eb925426119e1a9dc53d4286ade99a809"
        );
    }

    #[test]
    fn assesses_trojan_security_reasons() {
        let node = ProxyNode {
            node_type: "trojan".to_owned(),
            server: "example.com".to_owned(),
            port: 443,
            tls: Some(true),
            server_name: Some("cdn.example.com".to_owned()),
            alpn: Some("h2".to_owned()),
            skip_cert_verify: Some(false),
            ..ProxyNode::default()
        };

        let assessment = assess_security(
            &node,
            &TlsProbeStatus::Passed,
            &UdpProbeStatus::Passed("收到响应".to_owned()),
            &TtfbProbeStatus::Passed("收到首包".to_owned()),
            Some(320),
            1.0,
            0.0,
            Some(6),
            &StabilityMetrics {
                window_secs: 30,
                samples: 30,
                failures: 0,
                timeout_rate_percent: 0.0,
                max_consecutive_failures: 0,
                level: StabilityLevel::High,
            },
            3,
        );

        assert!(assessment.encryption_reason.contains("Trojan"));
        assert!(assessment.encryption_reason.contains("TLS"));
        assert_eq!(assessment.gfw_level, SecurityLevel::High);
        assert!(assessment.gfw_score >= 80);
        assert!(assessment.local_network_score >= 80);
        assert_eq!(assessment.anti_tracking_level, SecurityLevel::High);
        assert_eq!(assessment.live_network_level, SecurityLevel::High);
    }

    #[test]
    fn marks_weak_anti_tracking_for_plain_socks() {
        let node = ProxyNode {
            node_type: "socks5".to_owned(),
            server: "example.com".to_owned(),
            port: 1080,
            ..ProxyNode::default()
        };

        let assessment = assess_security(
            &node,
            &TlsProbeStatus::Skipped("协议默认跳过".to_owned()),
            &UdpProbeStatus::Skipped("协议默认跳过".to_owned()),
            &TtfbProbeStatus::Skipped("未定义".to_owned()),
            None,
            1.0,
            2.0,
            Some(8),
            &StabilityMetrics::disabled(),
            1,
        );

        assert_eq!(assessment.encryption_level, EncryptionLevel::Weak);
        assert_eq!(assessment.gfw_level, SecurityLevel::Low);
        assert!(assessment.local_network_score >= 50);
        assert_eq!(assessment.anti_tracking_level, SecurityLevel::Low);
        assert!(assessment.live_network_reason.contains("未开启持续稳定性窗口"));
    }

    #[test]
    fn rates_private_traffic_safety_high_for_guarded_clash_yaml() {
        let hints = SubscriptionConfigHints {
            kind: SubscriptionContentKind::ClashYaml,
            dns_enabled: Some(true),
            dns_listen: Some("0.0.0.0:1053".to_owned()),
            dns_enhanced_mode: Some("fake-ip".to_owned()),
            dns_nameserver_count: 2,
            dns_fallback_count: 1,
            dns_respect_rules: Some(true),
            mode: Some("rule".to_owned()),
            allow_lan: Some(false),
            bind_address: Some("127.0.0.1".to_owned()),
            mixed_port: Some(7890),
            tun_enabled: Some(true),
            tun_auto_route: Some(true),
            tun_strict_route: Some(true),
            tun_dns_hijack_count: 1,
            rule_count: 5,
            rule_provider_count: 2,
            external_controller: Some("127.0.0.1:9090".to_owned()),
            secret_present: true,
            ..SubscriptionConfigHints::default()
        };
        let nodes = vec![ProxyNode {
            node_type: "trojan".to_owned(),
            server: "example.com".to_owned(),
            port: 443,
            tls: Some(true),
            ..ProxyNode::default()
        }];

        let assessment = assess_subscription_local_privacy(&hints, &nodes);

        assert_eq!(assessment.level, SecurityLevel::High);
        assert!(assessment.reason.contains("启发式评估"));
    }

    #[test]
    fn rates_private_traffic_safety_low_for_node_list_without_guards() {
        let hints = SubscriptionConfigHints {
            kind: SubscriptionContentKind::ProxyList,
            ..SubscriptionConfigHints::default()
        };
        let nodes = vec![ProxyNode {
            node_type: "socks5".to_owned(),
            server: "example.com".to_owned(),
            port: 1080,
            skip_cert_verify: Some(true),
            ..ProxyNode::default()
        }];

        let assessment = assess_subscription_local_privacy(&hints, &nodes);

        assert_eq!(assessment.level, SecurityLevel::Low);
        assert!(assessment.reason.contains("节点列表"));
    }
}
