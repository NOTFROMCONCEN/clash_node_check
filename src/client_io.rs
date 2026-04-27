use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_yaml::{Mapping, Value};

use crate::subscription::{
    inspect_subscription_config, parse_subscription, ProxyNode, SubscriptionConfigHints,
    SubscriptionContentKind,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportPreset {
    Auto,
    Clash,
    FlClash,
    Karing,
}

impl ExportPreset {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Auto => "自动识别",
            Self::Clash => "Clash",
            Self::FlClash => "FlClash",
            Self::Karing => "Karing",
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ImportedNodes {
    pub nodes: Vec<ProxyNode>,
    pub config_hints: SubscriptionConfigHints,
    pub source_note: String,
}

#[derive(Clone, Debug)]
pub struct ExportOutcome {
    pub output_dir: PathBuf,
    pub files: Vec<PathBuf>,
    pub node_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum ClientKind {
    Karing,
    FlClash,
    Clash,
    Unknown,
}

impl ClientKind {
    fn label(&self) -> &'static str {
        match self {
            Self::Karing => "Karing",
            Self::FlClash => "FlClash",
            Self::Clash => "Clash",
            Self::Unknown => "Unknown",
        }
    }
}

#[derive(Default)]
struct ScanStats {
    scanned_files: usize,
    matched_files: usize,
    client_hits: BTreeMap<String, usize>,
}

impl ScanStats {
    fn add_hit(&mut self, client: ClientKind) {
        self.matched_files += 1;
        let key = client.label().to_owned();
        *self.client_hits.entry(key).or_insert(0) += 1;
    }

    fn summary(&self) -> String {
        let mut parts = Vec::new();
        for (name, count) in &self.client_hits {
            if name != "Unknown" {
                parts.push(format!("{name} {count}"));
            }
        }
        if parts.is_empty() {
            "未识别到明确客户端类型".to_owned()
        } else {
            parts.join(" / ")
        }
    }
}

pub fn load_nodes_from_source(input: &str) -> Result<ImportedNodes, String> {
    let source = input.trim();
    if source.is_empty() {
        return Err("输入为空：请填写订阅 URL 或本地客户端配置文件/目录路径".to_owned());
    }

    if source.starts_with("http://") || source.starts_with("https://") {
        return load_nodes_from_online_url(source);
    }

    let path = PathBuf::from(source);
    if !path.exists() {
        return Err(format!("输入既不是 URL，也不是有效本地路径：{source}"));
    }

    load_nodes_from_local_path(&path)
}

fn load_nodes_from_online_url(url: &str) -> Result<ImportedNodes, String> {
    let content = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(20))
        .user_agent("clash-node-checker/1.0")
        .build()
        .map_err(|error| format!("创建 HTTP 客户端失败：{error}"))?
        .get(url)
        .send()
        .map_err(|error| format!("下载订阅失败：{error}"))?
        .error_for_status()
        .map_err(|error| format!("订阅地址返回错误：{error}"))?
        .text()
        .map_err(|error| format!("读取订阅内容失败：{error}"))?;

    let nodes = parse_subscription(&content)?;
    let config_hints = inspect_subscription_config(&content);

    Ok(ImportedNodes {
        nodes,
        config_hints,
        source_note: "来源：在线订阅 URL".to_owned(),
    })
}

fn load_nodes_from_local_path(path: &Path) -> Result<ImportedNodes, String> {
    let mut candidates = Vec::new();
    let mut stats = ScanStats::default();

    if path.is_file() {
        if path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("zip"))
        {
            return Err(format!(
                "当前环境未启用 ZIP 直读，请先解压后导入目录：{}",
                path.display()
            ));
        }
        stats.scanned_files = 1;
        candidates.push(path.to_path_buf());
    } else {
        collect_candidate_files(path, &mut candidates, &mut stats.scanned_files)?;
    }

    if candidates.is_empty() {
        return Err("未找到可导入的配置文件（支持 yml/yaml/json/txt/conf/list）".to_owned());
    }

    let mut nodes = Vec::new();
    let mut config_hints = SubscriptionConfigHints::default();
    let mut has_clash_hints = false;

    for candidate in candidates {
        parse_text_file(
            &candidate,
            &mut nodes,
            &mut config_hints,
            &mut has_clash_hints,
            &mut stats,
        );
    }

    let deduped_nodes = dedup_nodes(nodes);
    if deduped_nodes.is_empty() {
        return Err("本地导入完成，但没有解析到可检测节点".to_owned());
    }

    let source_note = format!(
        "来源：本地批量导入（扫描 {} 文件，识别 {}，客户端：{}）",
        stats.scanned_files,
        stats.matched_files,
        stats.summary()
    );

    Ok(ImportedNodes {
        nodes: deduped_nodes,
        config_hints,
        source_note,
    })
}

fn collect_candidate_files(
    root: &Path,
    output: &mut Vec<PathBuf>,
    scanned_files: &mut usize,
) -> Result<(), String> {
    let entries =
        fs::read_dir(root).map_err(|error| format!("读取目录失败 {}: {error}", root.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("遍历目录失败 {}: {error}", root.display()))?;
        let path = entry.path();
        if path.is_dir() {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default()
                .to_ascii_lowercase();
            if matches!(name.as_str(), ".git" | "target" | "dist" | "node_modules") {
                continue;
            }
            collect_candidate_files(&path, output, scanned_files)?;
        } else if path.is_file() {
            *scanned_files += 1;
            if should_scan_file(&path) {
                output.push(path);
            }
        }
    }
    Ok(())
}

fn should_scan_file(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    matches!(
        ext.as_str(),
        "yml" | "yaml" | "json" | "txt" | "conf" | "list"
    )
}

fn parse_text_file(
    path: &Path,
    nodes: &mut Vec<ProxyNode>,
    config_hints: &mut SubscriptionConfigHints,
    has_clash_hints: &mut bool,
    stats: &mut ScanStats,
) {
    let Ok(bytes) = fs::read(path) else {
        return;
    };
    if bytes.is_empty() {
        return;
    }
    let content = String::from_utf8_lossy(&bytes).to_string();
    parse_content_blob(path, &content, nodes, config_hints, has_clash_hints, stats);
}

fn parse_content_blob(
    path_hint: &Path,
    content: &str,
    nodes: &mut Vec<ProxyNode>,
    config_hints: &mut SubscriptionConfigHints,
    has_clash_hints: &mut bool,
    stats: &mut ScanStats,
) {
    let Ok(mut parsed_nodes) = parse_subscription(content) else {
        return;
    };
    if parsed_nodes.is_empty() {
        return;
    }

    let hints = inspect_subscription_config(content);
    if hints.kind == SubscriptionContentKind::ClashYaml || !*has_clash_hints {
        *config_hints = hints.clone();
        *has_clash_hints = hints.kind == SubscriptionContentKind::ClashYaml;
    }

    let client = detect_client_kind(path_hint, content, &hints);
    stats.add_hit(client);
    nodes.append(&mut parsed_nodes);
}

fn detect_client_kind(
    path_hint: &Path,
    content: &str,
    hints: &SubscriptionConfigHints,
) -> ClientKind {
    let path_l = path_hint.to_string_lossy().to_ascii_lowercase();
    if path_l.contains("karing") {
        return ClientKind::Karing;
    }
    if path_l.contains("flclash") {
        return ClientKind::FlClash;
    }
    if path_l.contains("clash") {
        return ClientKind::Clash;
    }

    let content_l = content.to_ascii_lowercase();
    if content_l.contains("karing") {
        return ClientKind::Karing;
    }
    if content_l.contains("flclash") {
        return ClientKind::FlClash;
    }
    if hints.kind == SubscriptionContentKind::ClashYaml {
        return ClientKind::Clash;
    }

    ClientKind::Unknown
}

fn dedup_nodes(nodes: Vec<ProxyNode>) -> Vec<ProxyNode> {
    let mut seen = HashSet::new();
    let mut output = Vec::new();

    for node in nodes {
        let key = format!(
            "{}|{}|{}|{}|{}",
            node.node_type.to_ascii_lowercase(),
            node.server.to_ascii_lowercase(),
            node.port,
            node.uuid.clone().unwrap_or_default(),
            node.password.clone().unwrap_or_default()
        );
        if seen.insert(key) {
            output.push(node);
        }
    }

    output
}

pub fn export_nodes_for_clients(
    nodes: &[ProxyNode],
    preset: ExportPreset,
) -> Result<ExportOutcome, String> {
    let nodes = dedup_nodes(nodes.to_vec());
    if nodes.is_empty() {
        return Err("没有可导出的节点".to_owned());
    }

    let output_dir = output_dir_path()?;
    fs::create_dir_all(&output_dir)
        .map_err(|error| format!("创建导出目录失败 {}: {error}", output_dir.display()))?;

    let mut files = Vec::new();
    match preset {
        ExportPreset::Auto => {
            write_clash_yaml(&output_dir.join("clash-import.yaml"), &nodes, "AUTO")?;
            files.push(output_dir.join("clash-import.yaml"));

            write_clash_yaml(&output_dir.join("flclash-import.yaml"), &nodes, "FLCLASH")?;
            files.push(output_dir.join("flclash-import.yaml"));

            write_karing_uri_list(&output_dir.join("karing-import.txt"), &nodes)?;
            files.push(output_dir.join("karing-import.txt"));
        }
        ExportPreset::Clash => {
            write_clash_yaml(&output_dir.join("clash-import.yaml"), &nodes, "AUTO")?;
            files.push(output_dir.join("clash-import.yaml"));
        }
        ExportPreset::FlClash => {
            write_clash_yaml(&output_dir.join("flclash-import.yaml"), &nodes, "FLCLASH")?;
            files.push(output_dir.join("flclash-import.yaml"));
        }
        ExportPreset::Karing => {
            write_karing_uri_list(&output_dir.join("karing-import.txt"), &nodes)?;
            files.push(output_dir.join("karing-import.txt"));
            write_clash_yaml(&output_dir.join("karing-import.yaml"), &nodes, "KARING")?;
            files.push(output_dir.join("karing-import.yaml"));
        }
    }

    Ok(ExportOutcome {
        output_dir,
        files,
        node_count: nodes.len(),
    })
}

fn output_dir_path() -> Result<PathBuf, String> {
    let cwd = std::env::current_dir().map_err(|error| format!("读取当前目录失败: {error}"))?;
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("读取系统时间失败: {error}"))?
        .as_secs();
    Ok(cwd
        .join("dist")
        .join("exports")
        .join(format!("export-{ts}")))
}

fn write_clash_yaml(path: &Path, nodes: &[ProxyNode], group_name: &str) -> Result<(), String> {
    let mut root = Mapping::new();
    root.insert(
        Value::String("mixed-port".to_owned()),
        Value::Number(7890_i64.into()),
    );
    root.insert(Value::String("allow-lan".to_owned()), Value::Bool(false));
    root.insert(
        Value::String("mode".to_owned()),
        Value::String("rule".to_owned()),
    );
    root.insert(
        Value::String("log-level".to_owned()),
        Value::String("warning".to_owned()),
    );

    let mut proxies = Vec::new();
    let mut proxy_names = Vec::new();
    for node in nodes {
        proxies.push(node_to_clash_proxy(node));
        proxy_names.push(Value::String(node.name.clone()));
    }
    root.insert(
        Value::String("proxies".to_owned()),
        Value::Sequence(proxies),
    );

    let mut group = Mapping::new();
    group.insert(
        Value::String("name".to_owned()),
        Value::String(group_name.to_owned()),
    );
    group.insert(
        Value::String("type".to_owned()),
        Value::String("select".to_owned()),
    );
    group.insert(
        Value::String("proxies".to_owned()),
        Value::Sequence(proxy_names),
    );
    root.insert(
        Value::String("proxy-groups".to_owned()),
        Value::Sequence(vec![Value::Mapping(group)]),
    );
    root.insert(
        Value::String("rules".to_owned()),
        Value::Sequence(vec![Value::String(format!("MATCH,{group_name}"))]),
    );

    let content = serde_yaml::to_string(&Value::Mapping(root))
        .map_err(|error| format!("序列化 YAML 失败: {error}"))?;
    fs::write(path, content).map_err(|error| format!("写入文件失败 {}: {error}", path.display()))
}

fn node_to_clash_proxy(node: &ProxyNode) -> Value {
    let mut map = Mapping::new();
    insert_str(&mut map, "name", &node.name);
    insert_str(&mut map, "type", &node.node_type);
    insert_str(&mut map, "server", &node.server);
    insert_u16(&mut map, "port", node.port);
    insert_opt_bool(&mut map, "tls", node.tls);
    insert_opt_bool(&mut map, "skip-cert-verify", node.skip_cert_verify);
    insert_opt_str(&mut map, "cipher", node.cipher.as_deref());
    insert_opt_str(&mut map, "network", node.network.as_deref());
    insert_opt_str(&mut map, "sni", node.server_name.as_deref());
    insert_opt_str(&mut map, "uuid", node.uuid.as_deref());
    insert_opt_str(&mut map, "password", node.password.as_deref());
    insert_opt_str(&mut map, "flow", node.flow.as_deref());
    insert_opt_str(&mut map, "security", node.security.as_deref());
    insert_opt_str(&mut map, "alpn", node.alpn.as_deref());
    insert_opt_bool(&mut map, "udp", node.udp);
    insert_opt_str(
        &mut map,
        "client-fingerprint",
        node.client_fingerprint.as_deref(),
    );

    if node.reality_public_key.is_some() || node.reality_short_id.is_some() {
        let mut reality = Mapping::new();
        insert_opt_str(
            &mut reality,
            "public-key",
            node.reality_public_key.as_deref(),
        );
        insert_opt_str(&mut reality, "short-id", node.reality_short_id.as_deref());
        map.insert(
            Value::String("reality-opts".to_owned()),
            Value::Mapping(reality),
        );
    }

    Value::Mapping(map)
}

fn insert_str(map: &mut Mapping, key: &str, value: &str) {
    map.insert(
        Value::String(key.to_owned()),
        Value::String(value.to_owned()),
    );
}

fn insert_u16(map: &mut Mapping, key: &str, value: u16) {
    map.insert(
        Value::String(key.to_owned()),
        Value::Number((value as i64).into()),
    );
}

fn insert_opt_bool(map: &mut Mapping, key: &str, value: Option<bool>) {
    if let Some(value) = value {
        map.insert(Value::String(key.to_owned()), Value::Bool(value));
    }
}

fn insert_opt_str(map: &mut Mapping, key: &str, value: Option<&str>) {
    if let Some(value) = value {
        if !value.trim().is_empty() {
            map.insert(
                Value::String(key.to_owned()),
                Value::String(value.to_owned()),
            );
        }
    }
}

fn write_karing_uri_list(path: &Path, nodes: &[ProxyNode]) -> Result<(), String> {
    let mut lines = Vec::new();
    for node in nodes {
        if let Some(line) = node_to_uri(node) {
            lines.push(line);
        }
    }

    if lines.is_empty() {
        lines.push("# 当前节点无法转换为标准 URI，请改用 karing-import.yaml".to_owned());
    }

    fs::write(path, lines.join("\n"))
        .map_err(|error| format!("写入文件失败 {}: {error}", path.display()))
}

fn node_to_uri(node: &ProxyNode) -> Option<String> {
    let protocol = node.node_type.trim().to_ascii_lowercase();
    let name = encode_component(&node.name);
    let server = &node.server;
    let port = node.port;
    let sni_query = node
        .server_name
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(|value| format!("sni={}", encode_component(value)))
        .unwrap_or_default();

    match protocol.as_str() {
        "trojan" => {
            let password = node.password.as_deref()?;
            let mut query = vec!["security=tls".to_owned()];
            if !sni_query.is_empty() {
                query.push(sni_query);
            }
            Some(format!(
                "trojan://{}@{}:{}?{}#{}",
                encode_component(password),
                server,
                port,
                query.join("&"),
                name
            ))
        }
        "vless" => {
            let uuid = node.uuid.as_deref()?;
            let mut query = vec!["encryption=none".to_owned()];
            if let Some(security) = node.security.as_deref() {
                query.push(format!("security={}", encode_component(security)));
            } else if node.tls == Some(true) {
                query.push("security=tls".to_owned());
            }
            if let Some(network) = node.network.as_deref() {
                query.push(format!("type={}", encode_component(network)));
            }
            if !sni_query.is_empty() {
                query.push(sni_query);
            }
            Some(format!(
                "vless://{}@{}:{}?{}#{}",
                uuid,
                server,
                port,
                query.join("&"),
                name
            ))
        }
        "vmess" => {
            let uuid = node.uuid.as_deref()?;
            let mut query = Vec::new();
            if let Some(security) = node.security.as_deref() {
                query.push(format!("security={}", encode_component(security)));
            } else if node.tls == Some(true) {
                query.push("security=tls".to_owned());
            }
            if let Some(network) = node.network.as_deref() {
                query.push(format!("type={}", encode_component(network)));
            }
            if !sni_query.is_empty() {
                query.push(sni_query);
            }
            Some(format!(
                "vmess://{}@{}:{}?{}#{}",
                uuid,
                server,
                port,
                query.join("&"),
                name
            ))
        }
        "tuic" => {
            let uuid = node.uuid.as_deref()?;
            let password = node.password.as_deref()?;
            let mut query = vec!["congestion_control=bbr".to_owned()];
            if !sni_query.is_empty() {
                query.push(sni_query);
            }
            Some(format!(
                "tuic://{}:{}@{}:{}?{}#{}",
                uuid,
                encode_component(password),
                server,
                port,
                query.join("&"),
                name
            ))
        }
        "hysteria" | "hysteria2" => {
            let password = node.password.as_deref()?;
            let mut query = Vec::new();
            if !sni_query.is_empty() {
                query.push(sni_query);
            }
            Some(format!(
                "{}://{}@{}:{}{}#{}",
                protocol,
                encode_component(password),
                server,
                port,
                if query.is_empty() {
                    String::new()
                } else {
                    format!("?{}", query.join("&"))
                },
                name
            ))
        }
        _ => None,
    }
}

fn encode_component(input: &str) -> String {
    let mut output = String::new();
    for byte in input.as_bytes() {
        let ch = *byte as char;
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '~') {
            output.push(ch);
        } else {
            output.push('%');
            output.push_str(&format!("{:02X}", byte));
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn sample_node() -> ProxyNode {
        ProxyNode {
            name: "HK Demo".to_owned(),
            node_type: "trojan".to_owned(),
            server: "example.com".to_owned(),
            port: 443,
            tls: Some(true),
            password: Some("secret".to_owned()),
            server_name: Some("cdn.example.com".to_owned()),
            ..ProxyNode::default()
        }
    }

    #[test]
    fn exports_auto_preset_files() {
        let tmp = std::env::temp_dir().join(format!(
            "clash-node-checker-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        fs::create_dir_all(&tmp).unwrap();
        let old_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(&tmp).unwrap();

        let result = export_nodes_for_clients(&[sample_node()], ExportPreset::Auto);
        assert!(result.is_ok());
        let outcome = result.unwrap();
        assert_eq!(outcome.node_count, 1);
        assert!(outcome
            .files
            .iter()
            .any(|path| path.ends_with("clash-import.yaml")));
        assert!(outcome
            .files
            .iter()
            .any(|path| path.ends_with("flclash-import.yaml")));
        assert!(outcome
            .files
            .iter()
            .any(|path| path.ends_with("karing-import.txt")));

        std::env::set_current_dir(old_cwd).unwrap();
        let _ = fs::remove_dir_all(&tmp);
    }
}
