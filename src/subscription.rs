use std::collections::HashMap;

use base64::prelude::*;
use serde::Deserialize;
use serde_yaml::Value as YamlValue;

#[derive(Clone, Debug, Default)]
pub struct ProxyNode {
    pub name: String,
    pub node_type: String,
    pub server: String,
    pub port: u16,
    pub tls: Option<bool>,
    pub skip_cert_verify: Option<bool>,
    pub cipher: Option<String>,
    pub network: Option<String>,
    pub server_name: Option<String>,
    pub uuid: Option<String>,
    pub password: Option<String>,
    pub flow: Option<String>,
    pub security: Option<String>,
    pub alpn: Option<String>,
    pub udp: Option<bool>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum SubscriptionContentKind {
    ClashYaml,
    ProxyList,
    #[default]
    Unknown,
}

#[derive(Clone, Debug, Default)]
pub struct SubscriptionConfigHints {
    pub kind: SubscriptionContentKind,
    pub dns_enabled: Option<bool>,
    pub dns_listen: Option<String>,
    pub dns_enhanced_mode: Option<String>,
    pub dns_nameserver_count: usize,
    pub dns_fallback_count: usize,
    pub dns_respect_rules: Option<bool>,
    pub mode: Option<String>,
    pub allow_lan: Option<bool>,
    pub bind_address: Option<String>,
    pub mixed_port: Option<u16>,
    pub http_port: Option<u16>,
    pub socks_port: Option<u16>,
    pub redir_port: Option<u16>,
    pub tproxy_port: Option<u16>,
    pub tun_enabled: Option<bool>,
    pub tun_auto_route: Option<bool>,
    pub tun_strict_route: Option<bool>,
    pub tun_dns_hijack_count: usize,
    pub rule_count: usize,
    pub rule_provider_count: usize,
    pub external_controller: Option<String>,
    pub secret_present: bool,
}

#[derive(Debug, Deserialize)]
struct ClashConfig {
    proxies: Option<Vec<ClashProxy>>,
    dns: Option<ClashDnsConfig>,
    tun: Option<ClashTunConfig>,
    mode: Option<String>,
    rules: Option<Vec<String>>,
    #[serde(rename = "rule-providers")]
    rule_providers: Option<HashMap<String, YamlValue>>,
    #[serde(rename = "allow-lan")]
    allow_lan: Option<BoolValue>,
    #[serde(rename = "bind-address")]
    bind_address: Option<String>,
    #[serde(rename = "mixed-port")]
    mixed_port: Option<PortValue>,
    port: Option<PortValue>,
    #[serde(rename = "socks-port")]
    socks_port: Option<PortValue>,
    #[serde(rename = "redir-port")]
    redir_port: Option<PortValue>,
    #[serde(rename = "tproxy-port")]
    tproxy_port: Option<PortValue>,
    #[serde(rename = "external-controller")]
    external_controller: Option<String>,
    secret: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ClashDnsConfig {
    enable: Option<BoolValue>,
    listen: Option<String>,
    #[serde(rename = "enhanced-mode")]
    enhanced_mode: Option<String>,
    nameserver: Option<Vec<String>>,
    fallback: Option<Vec<String>>,
    #[serde(rename = "respect-rules")]
    respect_rules: Option<BoolValue>,
}

#[derive(Debug, Deserialize)]
struct ClashTunConfig {
    enable: Option<BoolValue>,
    #[serde(rename = "auto-route")]
    auto_route: Option<BoolValue>,
    #[serde(rename = "strict-route")]
    strict_route: Option<BoolValue>,
    #[serde(rename = "dns-hijack")]
    dns_hijack: Option<Vec<YamlValue>>,
}

#[derive(Debug, Deserialize)]
struct ClashProxy {
    name: Option<String>,
    #[serde(rename = "type")]
    node_type: Option<String>,
    server: Option<String>,
    port: Option<PortValue>,
    tls: Option<BoolValue>,
    #[serde(rename = "skip-cert-verify")]
    skip_cert_verify: Option<BoolValue>,
    cipher: Option<String>,
    network: Option<String>,
    sni: Option<String>,
    servername: Option<String>,
    uuid: Option<String>,
    password: Option<String>,
    flow: Option<String>,
    security: Option<String>,
    alpn: Option<StringOrList>,
    udp: Option<BoolValue>,
}

#[derive(Debug, Deserialize)]
struct VmessUriConfig {
    #[serde(rename = "ps", alias = "name")]
    name: Option<String>,
    #[serde(rename = "add", alias = "server")]
    server: Option<String>,
    port: Option<PortValue>,
    #[serde(rename = "id", alias = "uuid")]
    uuid: Option<String>,
    #[serde(rename = "scy", alias = "cipher")]
    cipher: Option<String>,
    #[serde(rename = "net", alias = "network")]
    network: Option<String>,
    #[serde(alias = "sni", alias = "servername")]
    server_name: Option<String>,
    tls: Option<String>,
    security: Option<String>,
    alpn: Option<StringOrList>,
    #[serde(rename = "allowInsecure")]
    skip_cert_verify: Option<BoolValue>,
    udp: Option<BoolValue>,
}

struct ParsedUriParts {
    host_port: String,
    query_map: HashMap<String, String>,
    userinfo: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum PortValue {
    Number(u16),
    Text(String),
}

impl PortValue {
    fn as_u16(&self) -> Option<u16> {
        match self {
            Self::Number(port) => Some(*port),
            Self::Text(port) => port.parse().ok(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum BoolValue {
    Bool(bool),
    Text(String),
}

impl BoolValue {
    fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(*value),
            Self::Text(value) => parse_bool_text(value),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum StringOrList {
    Text(String),
    List(Vec<String>),
}

impl StringOrList {
    fn as_text(&self) -> Option<String> {
        match self {
            Self::Text(value) => {
                if value.is_empty() {
                    None
                } else {
                    Some(value.clone())
                }
            }
            Self::List(values) => {
                let non_empty = values
                    .iter()
                    .map(|value| value.trim())
                    .filter(|value| !value.is_empty())
                    .collect::<Vec<_>>();
                if non_empty.is_empty() {
                    None
                } else {
                    Some(non_empty.join(","))
                }
            }
        }
    }
}

pub fn parse_subscription(content: &str) -> Result<Vec<ProxyNode>, String> {
    if let Ok(nodes) = parse_clash_yaml(content) {
        if !nodes.is_empty() {
            return Ok(nodes);
        }
    }

    let decoded = decode_base64_subscription(content).unwrap_or_else(|| content.to_owned());
    let nodes = decoded
        .lines()
        .filter_map(parse_proxy_uri_line)
        .collect::<Vec<_>>();

    if nodes.is_empty() {
        Err("没有解析到可检测的节点。请确认订阅是 Clash YAML 或常见代理 URI 列表。".to_owned())
    } else {
        Ok(nodes)
    }
}

pub fn inspect_subscription_config(content: &str) -> SubscriptionConfigHints {
    if let Ok(config) = serde_yaml::from_str::<ClashConfig>(content) {
        return SubscriptionConfigHints {
            kind: SubscriptionContentKind::ClashYaml,
            dns_enabled: config.dns.as_ref().and_then(|dns| dns.enable.as_ref()).and_then(BoolValue::as_bool),
            dns_listen: config
                .dns
                .as_ref()
                .and_then(|dns| dns.listen.as_deref())
                .map(str::to_owned)
                .filter(|value| !value.trim().is_empty()),
            dns_enhanced_mode: config
                .dns
                .as_ref()
                .and_then(|dns| dns.enhanced_mode.as_deref())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned),
            dns_nameserver_count: config
                .dns
                .as_ref()
                .and_then(|dns| dns.nameserver.as_ref())
                .map(Vec::len)
                .unwrap_or(0),
            dns_fallback_count: config
                .dns
                .as_ref()
                .and_then(|dns| dns.fallback.as_ref())
                .map(Vec::len)
                .unwrap_or(0),
            dns_respect_rules: config
                .dns
                .as_ref()
                .and_then(|dns| dns.respect_rules.as_ref())
                .and_then(BoolValue::as_bool),
            mode: config
                .mode
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned),
            allow_lan: config.allow_lan.as_ref().and_then(BoolValue::as_bool),
            bind_address: config
                .bind_address
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned),
            mixed_port: config.mixed_port.as_ref().and_then(PortValue::as_u16),
            http_port: config.port.as_ref().and_then(PortValue::as_u16),
            socks_port: config.socks_port.as_ref().and_then(PortValue::as_u16),
            redir_port: config.redir_port.as_ref().and_then(PortValue::as_u16),
            tproxy_port: config.tproxy_port.as_ref().and_then(PortValue::as_u16),
            tun_enabled: config
                .tun
                .as_ref()
                .and_then(|tun| tun.enable.as_ref())
                .and_then(BoolValue::as_bool),
            tun_auto_route: config
                .tun
                .as_ref()
                .and_then(|tun| tun.auto_route.as_ref())
                .and_then(BoolValue::as_bool),
            tun_strict_route: config
                .tun
                .as_ref()
                .and_then(|tun| tun.strict_route.as_ref())
                .and_then(BoolValue::as_bool),
            tun_dns_hijack_count: config
                .tun
                .as_ref()
                .and_then(|tun| tun.dns_hijack.as_ref())
                .map(Vec::len)
                .unwrap_or(0),
            rule_count: config.rules.as_ref().map(Vec::len).unwrap_or(0),
            rule_provider_count: config.rule_providers.as_ref().map(HashMap::len).unwrap_or(0),
            external_controller: config
                .external_controller
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned),
            secret_present: config.secret.as_deref().is_some_and(|value| !value.trim().is_empty()),
        };
    }

    let decoded = decode_base64_subscription(content).unwrap_or_else(|| content.to_owned());
    let kind = if decoded.lines().any(|line| line.trim().contains("://")) {
        SubscriptionContentKind::ProxyList
    } else {
        SubscriptionContentKind::Unknown
    };

    SubscriptionConfigHints {
        kind,
        ..Default::default()
    }
}

fn parse_clash_yaml(content: &str) -> Result<Vec<ProxyNode>, serde_yaml::Error> {
    let config = serde_yaml::from_str::<ClashConfig>(content)?;
    let nodes = config
        .proxies
        .unwrap_or_default()
        .into_iter()
        .filter_map(|proxy| {
            let server = proxy.server?;
            let port = proxy.port?.as_u16()?;

            Some(ProxyNode {
                name: proxy.name.unwrap_or_else(|| server.clone()),
                node_type: proxy.node_type.unwrap_or_else(|| "unknown".to_owned()),
                server,
                port,
                tls: proxy.tls.and_then(|value| value.as_bool()),
                skip_cert_verify: proxy.skip_cert_verify.and_then(|value| value.as_bool()),
                cipher: proxy.cipher,
                network: proxy.network,
                server_name: proxy.sni.or(proxy.servername),
                uuid: proxy.uuid,
                password: proxy.password,
                flow: proxy.flow,
                security: proxy.security,
                alpn: proxy.alpn.and_then(|value| value.as_text()),
                udp: proxy.udp.and_then(|value| value.as_bool()),
            })
        })
        .collect();

    Ok(nodes)
}

fn decode_base64_subscription(content: &str) -> Option<String> {
    decode_base64_text(content)
}

fn decode_base64_text(content: &str) -> Option<String> {
    let compact = content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<String>();

    BASE64_STANDARD
        .decode(compact.as_bytes())
        .or_else(|_| BASE64_STANDARD_NO_PAD.decode(compact.as_bytes()))
        .or_else(|_| BASE64_URL_SAFE_NO_PAD.decode(compact.as_bytes()))
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
}

fn parse_proxy_uri_line(line: &str) -> Option<ProxyNode> {
    let trimmed = line.trim();
    let (scheme, rest) = trimmed.split_once("://")?;
    let scheme_l = scheme.to_ascii_lowercase();

    match scheme_l.as_str() {
        "vmess" => parse_vmess_uri(trimmed, rest)
            .or_else(|| parse_standard_uri_node(trimmed, scheme, rest, None, None)),
        "trojan" => parse_standard_uri_node(
            trimmed,
            scheme,
            rest,
            None,
            parse_uri_parts(rest).userinfo,
        ),
        "vless" => parse_standard_uri_node(
            trimmed,
            scheme,
            rest,
            parse_uri_parts(rest).userinfo,
            None,
        ),
        "tuic" => {
            let parts = parse_uri_parts(rest);
            let (uuid, password) = split_userinfo_pair(parts.userinfo.as_deref());
            parse_standard_uri_node(trimmed, scheme, rest, uuid, password)
        }
        "hysteria" | "hysteria2" => {
            let parts = parse_uri_parts(rest);
            let (_, password) = split_userinfo_pair(parts.userinfo.as_deref());
            let password = password.or(parts.userinfo);
            parse_standard_uri_node(trimmed, scheme, rest, None, password)
        }
        _ => parse_standard_uri_node(trimmed, scheme, rest, None, None),
    }
}

fn parse_vmess_uri(trimmed: &str, rest: &str) -> Option<ProxyNode> {
    let payload = rest.split('#').next().unwrap_or(rest);
    let decoded = decode_base64_text(payload)?;
    let config = serde_json::from_str::<VmessUriConfig>(&decoded).ok()?;
    let server = config.server.as_deref().filter(|value| !value.is_empty())?;
    let port = config.port?.as_u16()?;
    let name = extract_fragment_name(trimmed)
        .or_else(|| config.name.as_deref().filter(|value| !value.is_empty()).map(str::to_owned))
        .unwrap_or_else(|| format!("{server}:{port}"));
    let security = normalize_vmess_security(config.security.as_deref(), config.tls.as_deref());
    let tls = infer_vmess_tls(security.as_deref());

    Some(ProxyNode {
        name,
        node_type: "vmess".to_owned(),
        server: server.to_owned(),
        port,
        tls,
        skip_cert_verify: config.skip_cert_verify.and_then(|value| value.as_bool()),
        cipher: normalize_optional_string(config.cipher),
        network: normalize_optional_string(config.network),
        server_name: normalize_optional_string(config.server_name),
        uuid: normalize_optional_string(config.uuid),
        password: None,
        flow: None,
        security,
        alpn: config.alpn.and_then(|value| value.as_text()),
        udp: config.udp.and_then(|value| value.as_bool()),
    })
}

fn parse_standard_uri_node(
    trimmed: &str,
    scheme: &str,
    rest: &str,
    uuid_override: Option<String>,
    password_override: Option<String>,
) -> Option<ProxyNode> {
    let parts = parse_uri_parts(rest);
    let (server, port) = parse_host_port(&parts.host_port)?;
    let name = extract_fragment_name(trimmed).unwrap_or_else(|| format!("{server}:{port}"));

    Some(ProxyNode {
        name,
        node_type: scheme.to_owned(),
        server,
        port,
        tls: infer_tls_from_uri(scheme, &parts.query_map),
        skip_cert_verify: infer_skip_cert_verify(&parts.query_map),
        cipher: infer_cipher(&parts.query_map),
        network: infer_network(&parts.query_map),
        server_name: infer_server_name(&parts.query_map),
        uuid: uuid_override.or_else(|| infer_uuid(&parts.query_map)),
        password: password_override.or_else(|| infer_password(&parts.query_map)),
        flow: infer_flow(&parts.query_map),
        security: infer_security(&parts.query_map),
        alpn: infer_alpn(&parts.query_map),
        udp: infer_udp(&parts.query_map),
    })
}

fn parse_uri_parts(rest: &str) -> ParsedUriParts {
    let without_fragment = rest.split('#').next().unwrap_or(rest);
    let (before_query, query) = without_fragment
        .split_once('?')
        .unwrap_or((without_fragment, ""));
    let (userinfo, host_port) = before_query
        .rsplit_once('@')
        .map(|(left, right)| (Some(left), right))
        .unwrap_or((None, before_query));

    ParsedUriParts {
        host_port: host_port.to_owned(),
        query_map: parse_query_map(query),
        userinfo: userinfo
            .and_then(|value| percent_decode_minimal(value).ok())
            .filter(|value| !value.is_empty()),
    }
}

fn extract_fragment_name(input: &str) -> Option<String> {
    input
        .split('#')
        .nth(1)
        .and_then(|value| percent_decode_minimal(value).ok())
        .filter(|value| !value.is_empty())
}

fn split_userinfo_pair(value: Option<&str>) -> (Option<String>, Option<String>) {
    let Some(value) = value else {
        return (None, None);
    };

    match value.split_once(':') {
        Some((left, right)) => (
            normalize_optional_string(Some(left.to_owned())),
            normalize_optional_string(Some(right.to_owned())),
        ),
        None => (normalize_optional_string(Some(value.to_owned())), None),
    }
}

fn normalize_optional_string(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_owned())
        }
    })
}

fn normalize_vmess_security(security: Option<&str>, tls: Option<&str>) -> Option<String> {
    if let Some(security) = normalize_optional_string(security.map(str::to_owned)) {
        return Some(security);
    }

    let tls = normalize_optional_string(tls.map(str::to_owned))?;
    match tls.to_ascii_lowercase().as_str() {
        "tls" | "xtls" | "reality" => Some(tls),
        "none" => Some("none".to_owned()),
        _ => Some(tls),
    }
}

fn infer_vmess_tls(security: Option<&str>) -> Option<bool> {
    let security = security?;
    let lower = security.to_ascii_lowercase();
    if matches!(lower.as_str(), "tls" | "xtls" | "reality") {
        Some(true)
    } else if lower == "none" {
        Some(false)
    } else {
        None
    }
}

fn parse_host_port(input: &str) -> Option<(String, u16)> {
    if let Some(stripped) = input.strip_prefix('[') {
        let (host, rest) = stripped.split_once(']')?;
        let port = rest.strip_prefix(':')?.parse().ok()?;
        return Some((host.to_owned(), port));
    }

    let (host, port) = input.rsplit_once(':')?;
    Some((host.to_owned(), port.parse().ok()?))
}

fn percent_decode_minimal(input: &str) -> Result<String, String> {
    let mut output = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3])
                .map_err(|error| error.to_string())?;
            if let Ok(value) = u8::from_str_radix(hex, 16) {
                output.push(value);
                index += 3;
                continue;
            }
        }

        output.push(bytes[index]);
        index += 1;
    }

    String::from_utf8(output).map_err(|error| error.to_string())
}

fn parse_query_map(query: &str) -> HashMap<String, String> {
    let mut query_map = HashMap::new();

    for part in query.split('&') {
        if part.is_empty() {
            continue;
        }

        let (raw_key, raw_value) = part.split_once('=').unwrap_or((part, ""));
        let key = percent_decode_minimal(raw_key).unwrap_or_else(|_| raw_key.to_owned());
        let value = percent_decode_minimal(raw_value).unwrap_or_else(|_| raw_value.to_owned());
        if !key.is_empty() {
            query_map.insert(key.to_ascii_lowercase(), value);
        }
    }

    query_map
}

fn infer_tls_from_uri(scheme: &str, query_map: &HashMap<String, String>) -> Option<bool> {
    if let Some(value) = query_map.get("security") {
        let lower = value.to_ascii_lowercase();
        if matches!(lower.as_str(), "tls" | "xtls" | "reality") {
            return Some(true);
        }
        if matches!(lower.as_str(), "none" | "plain") {
            return Some(false);
        }
    }

    if let Some(value) = query_map
        .get("tls")
        .and_then(|value| parse_bool_text(value))
    {
        return Some(value);
    }

    if matches!(
        scheme.to_ascii_lowercase().as_str(),
        "trojan" | "https" | "tuic" | "hysteria" | "hysteria2"
    ) {
        Some(true)
    } else {
        None
    }
}

fn infer_skip_cert_verify(query_map: &HashMap<String, String>) -> Option<bool> {
    let candidates = ["skip-cert-verify", "allowinsecure", "allow-insecure", "insecure"];
    for key in candidates {
        if let Some(value) = query_map.get(key).and_then(|value| parse_bool_text(value)) {
            return Some(value);
        }
    }
    None
}

fn infer_cipher(query_map: &HashMap<String, String>) -> Option<String> {
    let candidates = ["cipher", "encryption", "method"];
    for key in candidates {
        if let Some(value) = query_map.get(key).filter(|value| !value.is_empty()) {
            return Some(value.to_owned());
        }
    }
    None
}

fn infer_network(query_map: &HashMap<String, String>) -> Option<String> {
    let candidates = ["type", "network", "net"];
    for key in candidates {
        if let Some(value) = query_map.get(key).filter(|value| !value.is_empty()) {
            return Some(value.to_owned());
        }
    }
    None
}

fn infer_server_name(query_map: &HashMap<String, String>) -> Option<String> {
    let candidates = ["sni", "servername", "peer", "host"];
    for key in candidates {
        if let Some(value) = query_map.get(key).filter(|value| !value.is_empty()) {
            return Some(value.to_owned());
        }
    }
    None
}

fn infer_uuid(query_map: &HashMap<String, String>) -> Option<String> {
    let candidates = ["uuid", "id"];
    for key in candidates {
        if let Some(value) = query_map.get(key).filter(|value| !value.is_empty()) {
            return Some(value.to_owned());
        }
    }
    None
}

fn infer_password(query_map: &HashMap<String, String>) -> Option<String> {
    let candidates = ["password", "passwd", "token", "auth", "auth-str"];
    for key in candidates {
        if let Some(value) = query_map.get(key).filter(|value| !value.is_empty()) {
            return Some(value.to_owned());
        }
    }
    None
}

fn infer_flow(query_map: &HashMap<String, String>) -> Option<String> {
    query_map
        .get("flow")
        .filter(|value| !value.is_empty())
        .cloned()
}

fn infer_security(query_map: &HashMap<String, String>) -> Option<String> {
    query_map
        .get("security")
        .filter(|value| !value.is_empty())
        .cloned()
}

fn infer_alpn(query_map: &HashMap<String, String>) -> Option<String> {
    query_map
        .get("alpn")
        .filter(|value| !value.is_empty())
        .cloned()
}

fn infer_udp(query_map: &HashMap<String, String>) -> Option<bool> {
    let candidates = ["udp", "udp-relay"];
    for key in candidates {
        if let Some(value) = query_map.get(key).and_then(|value| parse_bool_text(value)) {
            return Some(value);
        }
    }
    None
}

fn parse_bool_text(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_clash_yaml() {
        let content = r#"
proxies:
  - name: Demo
    type: ss
    server: example.com
    port: 443
"#;

        let nodes = parse_subscription(content).unwrap();

        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "Demo");
        assert_eq!(nodes[0].server, "example.com");
        assert_eq!(nodes[0].port, 443);
    }

        #[test]
        fn inspects_clash_privacy_related_config() {
                let content = r#"
allow-lan: false
bind-address: 127.0.0.1
mixed-port: 7890
mode: rule
external-controller: 127.0.0.1:9090
secret: demo-secret
dns:
    enable: true
    listen: 0.0.0.0:1053
    enhanced-mode: fake-ip
    nameserver:
        - https://1.1.1.1/dns-query
    fallback:
        - tls://8.8.8.8:853
    respect-rules: true
tun:
    enable: true
    auto-route: true
    strict-route: true
    dns-hijack:
        - any:53
rules:
    - MATCH,Proxy
rule-providers:
    telegram:
        type: http
proxies:
    - name: Demo
      type: trojan
      server: example.com
      port: 443
"#;

                let hints = inspect_subscription_config(content);

                assert_eq!(hints.kind, SubscriptionContentKind::ClashYaml);
                assert_eq!(hints.dns_enabled, Some(true));
                assert_eq!(hints.dns_enhanced_mode.as_deref(), Some("fake-ip"));
                assert_eq!(hints.dns_nameserver_count, 1);
                assert_eq!(hints.tun_enabled, Some(true));
                assert_eq!(hints.rule_count, 1);
                assert_eq!(hints.rule_provider_count, 1);
                assert_eq!(hints.secret_present, true);
        }

        #[test]
        fn marks_proxy_uri_list_config_kind() {
                let hints = inspect_subscription_config(
                        "trojan://secret@example.com:443?sni=cdn.example.com#Trojan",
                );

                assert_eq!(hints.kind, SubscriptionContentKind::ProxyList);
        }

    #[test]
    fn parses_trojan_uri_password_from_userinfo() {
        let nodes = parse_subscription(
            "trojan://secret@example.com:443?sni=cdn.example.com&allowInsecure=1#Trojan",
        )
        .unwrap();

        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].node_type, "trojan");
        assert_eq!(nodes[0].password.as_deref(), Some("secret"));
        assert_eq!(nodes[0].tls, Some(true));
        assert_eq!(nodes[0].server_name.as_deref(), Some("cdn.example.com"));
        assert_eq!(nodes[0].skip_cert_verify, Some(true));
    }

    #[test]
    fn parses_vless_uri_uuid_from_userinfo() {
        let nodes = parse_subscription(
            "vless://550e8400-e29b-41d4-a716-446655440000@example.com:443?security=tls&sni=tls.example.com&alpn=h2#VLESS",
        )
        .unwrap();

        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].node_type, "vless");
        assert_eq!(
            nodes[0].uuid.as_deref(),
            Some("550e8400-e29b-41d4-a716-446655440000")
        );
        assert_eq!(nodes[0].tls, Some(true));
        assert_eq!(nodes[0].server_name.as_deref(), Some("tls.example.com"));
        assert_eq!(nodes[0].alpn.as_deref(), Some("h2"));
    }

    #[test]
    fn parses_vmess_base64_json_uri() {
        let json = r#"{
            "ps":"VMess Demo",
            "add":"vmess.example.com",
            "port":"443",
            "id":"550e8400-e29b-41d4-a716-446655440000",
            "aid":"0",
            "scy":"auto",
            "net":"ws",
            "tls":"tls",
            "sni":"edge.example.com",
            "alpn":"h2"
        }"#;
        let encoded = BASE64_STANDARD.encode(json);
        let nodes = parse_subscription(&format!("vmess://{encoded}")) .unwrap();

        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].node_type, "vmess");
        assert_eq!(nodes[0].name, "VMess Demo");
        assert_eq!(nodes[0].server, "vmess.example.com");
        assert_eq!(nodes[0].port, 443);
        assert_eq!(nodes[0].uuid.as_deref(), Some("550e8400-e29b-41d4-a716-446655440000"));
        assert_eq!(nodes[0].network.as_deref(), Some("ws"));
        assert_eq!(nodes[0].tls, Some(true));
        assert_eq!(nodes[0].security.as_deref(), Some("tls"));
        assert_eq!(nodes[0].server_name.as_deref(), Some("edge.example.com"));
        assert_eq!(nodes[0].alpn.as_deref(), Some("h2"));
    }

    #[test]
    fn parses_tuic_uri_uuid_and_password() {
        let nodes = parse_subscription(
            "tuic://550e8400-e29b-41d4-a716-446655440000:secret@example.com:443?alpn=h3&sni=tuic.example.com#TUIC",
        )
        .unwrap();

        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].node_type, "tuic");
        assert_eq!(
            nodes[0].uuid.as_deref(),
            Some("550e8400-e29b-41d4-a716-446655440000")
        );
        assert_eq!(nodes[0].password.as_deref(), Some("secret"));
        assert_eq!(nodes[0].tls, Some(true));
        assert_eq!(nodes[0].server_name.as_deref(), Some("tuic.example.com"));
    }
}
