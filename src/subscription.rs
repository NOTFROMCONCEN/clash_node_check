use base64::prelude::*;
use serde::Deserialize;

#[derive(Clone, Debug, Default)]
pub struct ProxyNode {
    pub name: String,
    pub node_type: String,
    pub server: String,
    pub port: u16,
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
    let host_port_part = without_fragment
        .rsplit('@')
        .next()
        .unwrap_or(without_fragment);
    let host_port_part = host_port_part.split('?').next().unwrap_or(host_port_part);

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
