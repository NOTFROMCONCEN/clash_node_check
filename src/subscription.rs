use std::collections::HashMap;

use base64::prelude::*;
use serde::Deserialize;

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

#[derive(Debug, Deserialize)]
struct ClashConfig {
    proxies: Option<Vec<ClashProxy>>,
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
    let without_fragment = rest.split('#').next().unwrap_or(rest);
    let query_part = without_fragment.split_once('?').map(|(_, query)| query);
    let host_port_part = without_fragment
        .rsplit('@')
        .next()
        .unwrap_or(without_fragment);
    let host_port_part = host_port_part.split('?').next().unwrap_or(host_port_part);
    let query_map = parse_query_map(query_part.unwrap_or_default());

    let (server, port) = parse_host_port(host_port_part)?;
    let name = trimmed
        .split('#')
        .nth(1)
        .and_then(|value| percent_decode_minimal(value).ok())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| format!("{server}:{port}"));

    Some(ProxyNode {
        name,
        node_type: scheme.to_owned(),
        server,
        port,
        tls: infer_tls_from_uri(scheme, &query_map),
        skip_cert_verify: infer_skip_cert_verify(&query_map),
        cipher: infer_cipher(&query_map),
        network: infer_network(&query_map),
        server_name: infer_server_name(&query_map),
        uuid: infer_uuid(&query_map),
        password: infer_password(&query_map),
        flow: infer_flow(&query_map),
        security: infer_security(&query_map),
        alpn: infer_alpn(&query_map),
        udp: infer_udp(&query_map),
    })
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
    let candidates = ["skip-cert-verify", "allowinsecure", "insecure"];
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
    let candidates = ["type", "network"];
    for key in candidates {
        if let Some(value) = query_map.get(key).filter(|value| !value.is_empty()) {
            return Some(value.to_owned());
        }
    }
    None
}

fn infer_server_name(query_map: &HashMap<String, String>) -> Option<String> {
    let candidates = ["sni", "peer", "host"];
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
    let candidates = ["password", "passwd", "token"];
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
}
