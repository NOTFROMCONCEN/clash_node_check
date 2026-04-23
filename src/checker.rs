use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::mpsc::Sender;
use std::thread;
use std::time::{Duration, Instant};

use crate::subscription::{parse_subscription, ProxyNode};

#[derive(Clone, Debug)]
pub struct CheckOptions {
    pub timeout: Duration,
}

impl Default for CheckOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(4),
        }
    }
}

#[derive(Clone, Debug)]
pub enum CheckEvent {
    Started { total: usize },
    NodeFinished(NodeCheckResult),
    Finished,
    Failed(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeStatus {
    Alive,
    Dead,
}

impl NodeStatus {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Alive => "存活",
            Self::Dead => "失败",
        }
    }
}

#[derive(Clone, Debug)]
pub struct NodeCheckResult {
    pub node: ProxyNode,
    pub status: NodeStatus,
    pub latency_ms: Option<u128>,
    pub message: String,
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
    tx.send(CheckEvent::Started { total: nodes.len() })
        .map_err(|error| error.to_string())?;

    let mut handles = Vec::with_capacity(nodes.len());

    for node in nodes {
        let node_tx = tx.clone();
        let node_options = options.clone();
        handles.push(thread::spawn(move || {
            let result = check_node(node, node_options.timeout);
            let _ = node_tx.send(CheckEvent::NodeFinished(result));
        }));
    }

    for handle in handles {
        let _ = handle.join();
    }

    tx.send(CheckEvent::Finished)
        .map_err(|error| error.to_string())
}

fn check_node(node: ProxyNode, timeout: Duration) -> NodeCheckResult {
    let address = format!("{}:{}", node.server, node.port);
    let socket_addrs = match address.to_socket_addrs() {
        Ok(addrs) => addrs.collect::<Vec<_>>(),
        Err(error) => {
            return NodeCheckResult {
                node,
                status: NodeStatus::Dead,
                latency_ms: None,
                message: format!("DNS 解析失败：{error}"),
            }
        }
    };

    if socket_addrs.is_empty() {
        return NodeCheckResult {
            node,
            status: NodeStatus::Dead,
            latency_ms: None,
            message: "没有可用地址".to_owned(),
        };
    }

    try_connect(node, &socket_addrs, timeout)
}

fn try_connect(node: ProxyNode, socket_addrs: &[SocketAddr], timeout: Duration) -> NodeCheckResult {
    let started_at = Instant::now();

    for socket_addr in socket_addrs {
        match TcpStream::connect_timeout(socket_addr, timeout) {
            Ok(_) => {
                return NodeCheckResult {
                    node,
                    status: NodeStatus::Alive,
                    latency_ms: Some(started_at.elapsed().as_millis()),
                    message: format!("TCP 可连接：{socket_addr}"),
                };
            }
            Err(last_error) => {
                if socket_addr == socket_addrs.last().expect("non-empty addresses") {
                    return NodeCheckResult {
                        node,
                        status: NodeStatus::Dead,
                        latency_ms: None,
                        message: format!("连接失败：{last_error}"),
                    };
                }
            }
        }
    }

    NodeCheckResult {
        node,
        status: NodeStatus::Dead,
        latency_ms: None,
        message: "连接失败".to_owned(),
    }
}
