use std::fs;
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use eframe::egui;
use egui::RichText;
use egui_extras::{Column, TableBuilder};

use crate::checker::{
    start_check, CheckEvent, CheckOptions, EncryptionLevel, NodeCheckResult, NodeStatus,
    ProtocolProbeStatus, SecurityLevel, StabilityLevel, StartSummary, TlsProbeStatus,
    TtfbProbeStatus, UdpProbeStatus,
};
use crate::update::{self, ReleaseInfo};

enum UpdateCheckState {
    Idle,
    Checking,
    UpToDate(ReleaseInfo),
    Available(ReleaseInfo),
    Failed(String),
}

pub struct ClashCheckerApp {
    subscription_url: String,
    timeout_secs: f32,
    attempts: u32,
    workers: u32,
    enable_tls_probe: bool,
    stability_window_secs: u32,
    search_text: String,
    row_filter: RowFilter,
    checking: bool,
    show_metric_guide: bool,
    show_node_detail: bool,
    selected_result_index: Option<usize>,
    table_mode: TableMode,
    status_line: String,
    start_summary: StartSummary,
    results: Vec<NodeCheckResult>,
    rx: Option<Receiver<CheckEvent>>,
    update_state: UpdateCheckState,
    update_rx: Option<Receiver<Result<ReleaseInfo, String>>>,
}

impl ClashCheckerApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        configure_chinese_font(&cc.egui_ctx);

        let mut app = Self {
            subscription_url: String::new(),
            timeout_secs: 5.0,
            attempts: 3,
            workers: 24,
            enable_tls_probe: true,
            stability_window_secs: 0,
            search_text: String::new(),
            row_filter: RowFilter::All,
            checking: false,
            show_metric_guide: false,
            show_node_detail: false,
            selected_result_index: None,
            table_mode: TableMode::Compact,
            status_line: "输入 Clash 订阅地址后开始检测".to_owned(),
            start_summary: StartSummary::default(),
            results: Vec::new(),
            rx: None,
            update_state: UpdateCheckState::Idle,
            update_rx: None,
        };

        app.trigger_update_check();
        app
    }

    fn trigger_update_check(&mut self) {
        if self.update_rx.is_some() {
            return;
        }

        let (tx, rx) = mpsc::channel();
        self.update_state = UpdateCheckState::Checking;
        self.update_rx = Some(rx);

        std::thread::spawn(move || {
            let result = update::check_latest_release();
            let _ = tx.send(result);
        });
    }

    fn start(&mut self) {
        let url = self.subscription_url.trim().to_owned();
        if url.is_empty() {
            self.status_line = "请先输入订阅地址".to_owned();
            return;
        }

        let (tx, rx) = mpsc::channel();
        let options = CheckOptions {
            timeout: Duration::from_secs_f32(self.timeout_secs.max(1.0)),
            attempts: self.attempts.clamp(1, 10) as u8,
            workers: self.workers.clamp(1, 128) as usize,
            enable_tls_probe: self.enable_tls_probe,
            stability_window_secs: self.stability_window_secs.clamp(0, 60) as u16,
        };

        self.results.clear();
        self.start_summary = StartSummary::default();
        self.selected_result_index = None;
        self.show_node_detail = false;
        self.rx = Some(rx);
        self.checking = true;
        self.status_line = "正在下载订阅并执行多项检测...".to_owned();

        start_check(url, options, tx);
    }

    fn drain_events(&mut self) {
        let mut should_clear_rx = false;
        let mut should_clear_update_rx = false;

        if let Some(rx) = &self.rx {
            while let Ok(event) = rx.try_recv() {
                match event {
                    CheckEvent::Started(summary) => {
                        self.start_summary = summary.clone();
                        self.results.reserve(summary.total);
                        self.status_line = format!(
                            "解析到 {} 个节点（唯一端点 {}，重复端点 {}，重名 {}），开始检测...",
                            summary.total,
                            summary.unique_endpoints,
                            summary.duplicate_endpoints,
                            summary.duplicate_names
                        );
                    }
                    CheckEvent::NodeFinished(result) => {
                        self.results.push(result);
                        let checked = self.results.len();
                        self.status_line = format!(
                            "已检测 {checked}/{} | TCP可连 {} | UDP通过 {} | TTFB通过 {} | 严格通过 {} | 失败 {}",
                            self.start_summary.total.max(checked),
                            self.tcp_alive_count(),
                            self.udp_pass_count(),
                            self.ttfb_pass_count(),
                            self.pass_count(),
                            self.fail_count()
                        );
                    }
                    CheckEvent::Finished => {
                        self.checking = false;
                        self.status_line = format!(
                            "检测完成：共 {} 个，TCP可连 {} 个，UDP通过 {} 个，TTFB通过 {} 个，严格通过 {} 个，失败 {} 个",
                            self.results.len(),
                            self.tcp_alive_count(),
                            self.udp_pass_count(),
                            self.ttfb_pass_count(),
                            self.pass_count(),
                            self.fail_count()
                        );
                        should_clear_rx = true;
                    }
                    CheckEvent::Failed(error) => {
                        self.checking = false;
                        self.status_line = error;
                        should_clear_rx = true;
                    }
                }
            }
        }

        if let Some(update_rx) = &self.update_rx {
            while let Ok(event) = update_rx.try_recv() {
                self.update_state = match event {
                    Ok(release) if release.update_available => UpdateCheckState::Available(release),
                    Ok(release) => UpdateCheckState::UpToDate(release),
                    Err(error) => UpdateCheckState::Failed(error),
                };
                should_clear_update_rx = true;
            }
        }

        if should_clear_rx {
            self.rx = None;
        }

        if should_clear_update_rx {
            self.update_rx = None;
        }
    }

    fn version_update_card_ui(&mut self, ui: &mut egui::Ui) {
        panel_card(
            ui,
            "版本与更新",
            Some("当前版本与 GitHub Release 更新状态"),
            |ui| {
                let current_version = format!("v{}", update::current_version());
                ui.horizontal_wrapped(|ui| {
                    metric_chip(ui, "当前版本", &current_version);
                    if ui
                        .add_enabled(
                            self.update_rx.is_none(),
                            egui::Button::new(if self.update_rx.is_some() {
                                "检查中..."
                            } else {
                                "检查更新"
                            }),
                        )
                        .clicked()
                    {
                        self.trigger_update_check();
                    }
                    ui.hyperlink_to("GitHub Releases", update::release_repository_url());
                });

                ui.add_space(8.0);

                match &self.update_state {
                    UpdateCheckState::Idle => {
                        ui.label("启动后会自动检查一次 GitHub Release 更新状态。");
                    }
                    UpdateCheckState::Checking => {
                        ui.horizontal_wrapped(|ui| {
                            ui.spinner();
                            ui.label("正在从 GitHub Release 检查最新版本...");
                        });
                    }
                    UpdateCheckState::UpToDate(release) => {
                        let response = ui.colored_label(
                            egui::Color32::from_rgb(32, 145, 91),
                            format!("当前已是最新版本 v{}", release.latest_version),
                        );
                        if let Some(published_at) = release.published_at.as_deref() {
                            response.on_hover_text(format!("最近一次 Release 发布时间: {published_at}"));
                        }
                        if let Some(notes) = release.notes.as_deref() {
                            ui.add_space(4.0);
                            ui.add(egui::Label::new(short_text(notes, 160)).wrap());
                        }
                    }
                    UpdateCheckState::Available(release) => {
                        let mut hover_text = format!(
                            "发现新版本 v{}，当前版本 v{}",
                            release.latest_version, release.current_version
                        );
                        if let Some(asset_name) = release.asset_name.as_deref() {
                            hover_text.push_str(&format!("\n推荐资产: {asset_name}"));
                        }
                        if let Some(published_at) = release.published_at.as_deref() {
                            hover_text.push_str(&format!("\n发布时间: {published_at}"));
                        }

                        let response = ui.colored_label(
                            egui::Color32::from_rgb(194, 122, 0),
                            format!(
                                "发现新版本 v{}，当前为 v{}",
                                release.latest_version, release.current_version
                            ),
                        );
                        response.on_hover_text(hover_text);

                        ui.add_space(4.0);
                        ui.horizontal_wrapped(|ui| {
                            if let Some(download_url) = release.download_url.as_deref() {
                                ui.hyperlink_to("下载资产", download_url);
                            }
                            ui.hyperlink_to("查看 Release", &release.release_page);
                        });

                        if let Some(notes) = release.notes.as_deref() {
                            ui.add_space(4.0);
                            ui.add(egui::Label::new(short_text(notes, 160)).wrap());
                        }
                    }
                    UpdateCheckState::Failed(error) => {
                        ui.colored_label(
                            egui::Color32::from_rgb(194, 122, 0),
                            format!("更新检查失败：{error}"),
                        );
                    }
                }

                ui.add_space(6.0);
                ui.label(
                    RichText::new(format!(
                        "Release 源：{}",
                        update::release_repository_slug()
                    ))
                    .small()
                    .weak(),
                );
            },
        );
    }

    fn pass_count(&self) -> usize {
        self.results
            .iter()
            .filter(|result| result.status == NodeStatus::Pass)
            .count()
    }

    fn warn_count(&self) -> usize {
        self.results
            .iter()
            .filter(|result| result.status == NodeStatus::Warn)
            .count()
    }

    fn fail_count(&self) -> usize {
        self.results
            .iter()
            .filter(|result| result.status == NodeStatus::Fail)
            .count()
    }

    fn tcp_alive_count(&self) -> usize {
        self.results
            .iter()
            .filter(|result| result.tcp_alive())
            .count()
    }

    fn dns_ok_count(&self) -> usize {
        self.results.iter().filter(|result| result.dns_ok).count()
    }

    fn tls_passed_count(&self) -> usize {
        self.results
            .iter()
            .filter(|result| result.tls_status.is_passed())
            .count()
    }

    fn protocol_probe_pass_count(&self) -> usize {
        self.results
            .iter()
            .filter(|result| result.protocol_probe.is_passed())
            .count()
    }

    fn protocol_probe_fail_count(&self) -> usize {
        self.results
            .iter()
            .filter(|result| matches!(result.protocol_probe, ProtocolProbeStatus::Failed(_)))
            .count()
    }

    fn protocol_probe_partial_count(&self) -> usize {
        self.results
            .iter()
            .filter(|result| {
                matches!(
                    result.protocol_probe,
                    ProtocolProbeStatus::Partial(_) | ProtocolProbeStatus::Skipped(_)
                )
            })
            .count()
    }

    fn udp_pass_count(&self) -> usize {
        self.results
            .iter()
            .filter(|result| result.udp_status.is_passed())
            .count()
    }

    fn udp_fail_count(&self) -> usize {
        self.results
            .iter()
            .filter(|result| matches!(result.udp_status, UdpProbeStatus::Failed(_)))
            .count()
    }

    fn ttfb_pass_count(&self) -> usize {
        self.results
            .iter()
            .filter(|result| result.ttfb_status.is_passed())
            .count()
    }

    fn ttfb_fail_count(&self) -> usize {
        self.results
            .iter()
            .filter(|result| matches!(result.ttfb_status, TtfbProbeStatus::Failed(_)))
            .count()
    }

    fn stability_high_count(&self) -> usize {
        self.results
            .iter()
            .filter(|result| result.stability.level == StabilityLevel::High)
            .count()
    }

    fn high_security_count(&self) -> usize {
        self.results
            .iter()
            .filter(|result| result.security.security_level == SecurityLevel::High)
            .count()
    }

    fn medium_security_count(&self) -> usize {
        self.results
            .iter()
            .filter(|result| result.security.security_level == SecurityLevel::Medium)
            .count()
    }

    fn low_security_count(&self) -> usize {
        self.results
            .iter()
            .filter(|result| result.security.security_level == SecurityLevel::Low)
            .count()
    }

    fn strong_encryption_count(&self) -> usize {
        self.results
            .iter()
            .filter(|result| result.security.encryption_level == EncryptionLevel::Strong)
            .count()
    }

    fn moderate_encryption_count(&self) -> usize {
        self.results
            .iter()
            .filter(|result| result.security.encryption_level == EncryptionLevel::Moderate)
            .count()
    }

    fn weak_or_plaintext_count(&self) -> usize {
        self.results
            .iter()
            .filter(|result| {
                matches!(
                    result.security.encryption_level,
                    EncryptionLevel::Weak | EncryptionLevel::Plaintext
                )
            })
            .count()
    }

    fn percent(&self, count: usize) -> f32 {
        if self.results.is_empty() {
            0.0
        } else {
            count as f32 / self.results.len() as f32 * 100.0
        }
    }

    fn subscription_score_summary(&self) -> SubscriptionAggregateScore {
        compute_subscription_score(&self.results, &self.start_summary)
    }

    fn summary_ui(&self, ui: &mut egui::Ui) {
        let subscription_score = self.subscription_score_summary();
        let mut sections = vec![
            vec![
                (
                    "订阅综合",
                    format!("{} / 100 ({})", subscription_score.score, subscription_score.grade),
                ),
                (
                    "本机私流",
                    format!("{}（启发式）", self.start_summary.local_privacy.level.label()),
                ),
                ("总节点", self.results.len().to_string()),
                (
                    "TCP可连",
                    format!(
                        "{} ({:.1}%)",
                        self.tcp_alive_count(),
                        self.percent(self.tcp_alive_count())
                    ),
                ),
                (
                    "严格通过",
                    format!(
                        "{} ({:.1}%)",
                        self.pass_count(),
                        self.percent(self.pass_count())
                    ),
                ),
                ("部分通过", self.warn_count().to_string()),
                ("失败", self.fail_count().to_string()),
            ],
            vec![
                (
                    "DNS通过",
                    format!(
                        "{} ({:.1}%)",
                        self.dns_ok_count(),
                        self.percent(self.dns_ok_count())
                    ),
                ),
                (
                    "TLS通过",
                    format!(
                        "{} ({:.1}%)",
                        self.tls_passed_count(),
                        self.percent(self.tls_passed_count())
                    ),
                ),
                ("重复端点", self.start_summary.duplicate_endpoints.to_string()),
                ("重名节点", self.start_summary.duplicate_names.to_string()),
                ("TLS目标", self.start_summary.tls_target_count.to_string()),
                (
                    "协议通过",
                    format!(
                        "{} ({:.1}%)",
                        self.protocol_probe_pass_count(),
                        self.percent(self.protocol_probe_pass_count())
                    ),
                ),
                ("协议部分", self.protocol_probe_partial_count().to_string()),
                ("协议失败", self.protocol_probe_fail_count().to_string()),
                (
                    "UDP通过",
                    format!(
                        "{} ({:.1}%)",
                        self.udp_pass_count(),
                        self.percent(self.udp_pass_count())
                    ),
                ),
                ("UDP失败", self.udp_fail_count().to_string()),
                (
                    "TTFB通过",
                    format!(
                        "{} ({:.1}%)",
                        self.ttfb_pass_count(),
                        self.percent(self.ttfb_pass_count())
                    ),
                ),
                ("TTFB失败", self.ttfb_fail_count().to_string()),
            ],
            vec![
                (
                    "高安全",
                    format!(
                        "{} ({:.1}%)",
                        self.high_security_count(),
                        self.percent(self.high_security_count())
                    ),
                ),
                (
                    "中安全",
                    format!(
                        "{} ({:.1}%)",
                        self.medium_security_count(),
                        self.percent(self.medium_security_count())
                    ),
                ),
                (
                    "低安全",
                    format!(
                        "{} ({:.1}%)",
                        self.low_security_count(),
                        self.percent(self.low_security_count())
                    ),
                ),
                (
                    "强加密",
                    format!(
                        "{} ({:.1}%)",
                        self.strong_encryption_count(),
                        self.percent(self.strong_encryption_count())
                    ),
                ),
                (
                    "中加密",
                    format!(
                        "{} ({:.1}%)",
                        self.moderate_encryption_count(),
                        self.percent(self.moderate_encryption_count())
                    ),
                ),
                (
                    "弱/明文",
                    format!(
                        "{} ({:.1}%)",
                        self.weak_or_plaintext_count(),
                        self.percent(self.weak_or_plaintext_count())
                    ),
                ),
            ],
        ];

        if self.stability_window_secs > 0 {
            sections[2].push((
                "稳定高",
                format!(
                    "{} ({:.1}%)",
                    self.stability_high_count(),
                    self.percent(self.stability_high_count())
                ),
            ));
        }

        for (index, items) in sections.iter().enumerate() {
            summary_tile_grid(ui, items);
            if index + 1 < sections.len() {
                ui.add_space(8.0);
            }
        }
    }

    fn filtered_result_indices(&self) -> Vec<usize> {
        self.results
            .iter()
            .enumerate()
            .filter(|(_, result)| self.matches_filter(result))
            .map(|(index, _)| index)
            .collect()
    }

    fn matches_filter(&self, result: &NodeCheckResult) -> bool {
        let filter_match = match self.row_filter {
            RowFilter::All => true,
            RowFilter::Pass => result.status == NodeStatus::Pass,
            RowFilter::Warn => result.status == NodeStatus::Warn,
            RowFilter::Fail => result.status == NodeStatus::Fail,
            RowFilter::HighRisk => {
                result.security.security_level == SecurityLevel::Low
                    || result.security.encryption_level == EncryptionLevel::Plaintext
                    || result.security.gfw_level == SecurityLevel::Low
                    || result.security.anti_tracking_level == SecurityLevel::Low
                    || result.security.local_network_level == SecurityLevel::Low
                    || result.security.live_network_level == SecurityLevel::Low
                    || matches!(result.stability.level, StabilityLevel::Low)
                    || matches!(result.udp_status, UdpProbeStatus::Failed(_))
            }
        };
        if !filter_match {
            return false;
        }

        let keyword = self.search_text.trim().to_ascii_lowercase();
        if keyword.is_empty() {
            return true;
        }

        let message = format!(
            "{} {} {} {} {}",
            result.node.name,
            result.node.server,
            result.node.node_type,
            result.message,
            result.security.note
        )
        .to_ascii_lowercase();
        message.contains(&keyword)
    }

    fn table_ui(&mut self, ui: &mut egui::Ui, row_indices: &[usize]) {
        match self.table_mode {
            TableMode::Compact => self.table_ui_compact(ui, row_indices),
            TableMode::Full => self.table_ui_full(ui, row_indices),
        }
    }

    fn table_ui_compact(&mut self, ui: &mut egui::Ui, row_indices: &[usize]) {
        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .vscroll(true)
            .max_scroll_height(result_table_scroll_height())
            .sense(egui::Sense::click())
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::initial(280.0).at_least(180.0))
            .column(Column::initial(80.0).at_least(64.0))
            .column(Column::initial(260.0).at_least(160.0))
            .column(Column::initial(80.0).at_least(60.0))
            .column(Column::initial(90.0).at_least(70.0))
            .column(Column::initial(90.0).at_least(70.0))
            .column(Column::initial(190.0).at_least(140.0))
            .column(Column::initial(190.0).at_least(140.0))
            .column(Column::initial(90.0).at_least(70.0))
            .column(Column::initial(90.0).at_least(70.0))
            .column(Column::initial(560.0).at_least(300.0))
            .header(28.0, |mut header| {
                header.col(|ui| {
                    ui.strong("节点");
                });
                header.col(|ui| {
                    ui.strong("协议");
                });
                header.col(|ui| {
                    ui.strong("服务器");
                });
                header.col(|ui| {
                    ui.strong("端口");
                });
                header.col(|ui| {
                    ui.strong("TCP均延迟");
                });
                header.col(|ui| {
                    ui.strong("TCP成功");
                });
                header.col(|ui| {
                    ui.strong("TLS");
                });
                header.col(|ui| {
                    ui.strong("UDP");
                });
                header.col(|ui| {
                    ui.strong("安全");
                });
                header.col(|ui| {
                    ui.strong("评分");
                });
                header.col(|ui| {
                    ui.strong("状态");
                });
            })
            .body(|body| {
                body.rows(28.0, row_indices.len(), |mut row| {
                    let result_index = row_indices[row.index()];
                    let is_selected = self.selected_result_index == Some(result_index);
                    row.set_selected(is_selected);

                    let result = &self.results[result_index];
                    row.col(|ui| {
                        ui.label(&result.node.name);
                    });
                    row.col(|ui| {
                        ui.label(&result.node.node_type);
                    });
                    row.col(|ui| {
                        ui.label(&result.node.server);
                    });
                    row.col(|ui| {
                        ui.label(result.node.port.to_string());
                    });
                    row.col(|ui| {
                        ui.label(
                            result
                                .tcp_avg_latency_ms
                                .map(|value| format!("{value} ms"))
                                .unwrap_or_else(|| "-".to_owned()),
                        );
                    });
                    row.col(|ui| {
                        ui.label(format!("{}/{}", result.tcp_successes, result.tcp_attempts));
                    });
                    row.col(|ui| {
                        let (tls_text, tls_color) = match &result.tls_status {
                            TlsProbeStatus::Passed => (
                                result
                                    .tls_latency_ms
                                    .map(|latency| format!("通过 {latency}ms"))
                                    .unwrap_or_else(|| "通过".to_owned()),
                                egui::Color32::from_rgb(32, 145, 91),
                            ),
                            TlsProbeStatus::Disabled => {
                                ("关闭".to_owned(), ui.visuals().weak_text_color())
                            }
                            TlsProbeStatus::Skipped(reason) => {
                                (format!("跳过({reason})"), ui.visuals().weak_text_color())
                            }
                            TlsProbeStatus::Failed(reason) => (
                                format!("失败({reason})"),
                                egui::Color32::from_rgb(190, 64, 64),
                            ),
                        };
                        let response = ui.colored_label(tls_color, short_text(&tls_text, 24));
                        response.on_hover_text(tls_text);
                    });
                    row.col(|ui| {
                        let (udp_text, udp_color) = match &result.udp_status {
                            UdpProbeStatus::Passed(message) => (
                                result
                                    .udp_latency_ms
                                    .map(|latency| format!("通过({message}, {latency}ms)"))
                                    .unwrap_or_else(|| format!("通过({message})")),
                                egui::Color32::from_rgb(32, 145, 91),
                            ),
                            UdpProbeStatus::Partial(message) => (
                                format!("部分({message})"),
                                egui::Color32::from_rgb(194, 122, 0),
                            ),
                            UdpProbeStatus::Failed(message) => (
                                format!("失败({message})"),
                                egui::Color32::from_rgb(190, 64, 64),
                            ),
                            UdpProbeStatus::Skipped(message) => {
                                (format!("跳过({message})"), ui.visuals().weak_text_color())
                            }
                        };
                        let response = ui.colored_label(udp_color, short_text(&udp_text, 24));
                        response.on_hover_text(udp_text);
                    });
                    row.col(|ui| {
                        let (security_text, security_color) = match result.security.security_level {
                            SecurityLevel::High => ("高", egui::Color32::from_rgb(32, 145, 91)),
                            SecurityLevel::Medium => ("中", egui::Color32::from_rgb(194, 122, 0)),
                            SecurityLevel::Low => ("低", egui::Color32::from_rgb(190, 64, 64)),
                            SecurityLevel::Unknown => ("未知", ui.visuals().weak_text_color()),
                        };
                        let response = ui.colored_label(security_color, security_text);
                        response.on_hover_text(if result.security.security_reason.is_empty() {
                            format!("安全等级: {}", result.security.security_level.label())
                        } else {
                            format!(
                                "安全等级: {}\n{}",
                                result.security.security_level.label(),
                                result.security.security_reason
                            )
                        });
                    });
                    row.col(|ui| {
                        ui.label(format!("{} / 100", result.security.score));
                    });
                    row.col(|ui| {
                        let color = match result.status {
                            NodeStatus::Pass => egui::Color32::from_rgb(32, 145, 91),
                            NodeStatus::Warn => egui::Color32::from_rgb(194, 122, 0),
                            NodeStatus::Fail => egui::Color32::from_rgb(190, 64, 64),
                        };
                        let full = format!("{} - {}", result.status.label(), result.message);
                        let response = ui.label(RichText::new(short_text(&full, 50)).color(color));
                        response.on_hover_text(full);
                    });

                    let row_response = row.response();
                    if row_response.clicked() {
                        self.selected_result_index = Some(result_index);
                    }
                    if row_response.double_clicked() {
                        self.selected_result_index = Some(result_index);
                        self.show_node_detail = true;
                    }
                });
            });
    }

    fn table_ui_full(&mut self, ui: &mut egui::Ui, row_indices: &[usize]) {
        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .vscroll(true)
            .max_scroll_height(result_table_scroll_height())
            .sense(egui::Sense::click())
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::initial(280.0).at_least(180.0))
            .column(Column::initial(80.0).at_least(64.0))
            .column(Column::initial(240.0).at_least(140.0))
            .column(Column::initial(80.0).at_least(60.0))
            .column(Column::initial(90.0).at_least(70.0))
            .column(Column::initial(90.0).at_least(70.0))
            .column(Column::initial(90.0).at_least(70.0))
            .column(Column::initial(96.0).at_least(76.0))
            .column(Column::initial(230.0).at_least(160.0))
            .column(Column::initial(220.0).at_least(160.0))
            .column(Column::initial(180.0).at_least(120.0))
            .column(Column::initial(240.0).at_least(160.0))
            .column(Column::initial(360.0).at_least(220.0))
            .column(Column::initial(90.0).at_least(70.0))
            .column(Column::initial(90.0).at_least(70.0))
            .column(Column::initial(90.0).at_least(70.0))
            .column(Column::initial(620.0).at_least(340.0))
            .header(28.0, |mut header| {
                header.col(|ui| {
                    ui.strong("节点");
                });
                header.col(|ui| {
                    ui.strong("协议");
                });
                header.col(|ui| {
                    ui.strong("服务器");
                });
                header.col(|ui| {
                    ui.strong("端口");
                });
                header.col(|ui| {
                    ui.strong("TCP均延迟");
                });
                header.col(|ui| {
                    ui.strong("TCP成功");
                });
                header.col(|ui| {
                    ui.strong("抖动");
                });
                header.col(|ui| {
                    ui.strong("丢包");
                });
                header.col(|ui| {
                    ui.strong("UDP");
                });
                header.col(|ui| {
                    ui.strong("TTFB");
                });
                header.col(|ui| {
                    ui.strong("稳定性");
                });
                header.col(|ui| {
                    ui.strong("协议探测");
                });
                header.col(|ui| {
                    ui.strong("TLS");
                });
                header.col(|ui| {
                    ui.strong("安全");
                });
                header.col(|ui| {
                    ui.strong("加密");
                });
                header.col(|ui| {
                    ui.strong("评分");
                });
                header.col(|ui| {
                    ui.strong("状态");
                });
            })
            .body(|body| {
                body.rows(28.0, row_indices.len(), |mut row| {
                    let result_index = row_indices[row.index()];
                    let is_selected = self.selected_result_index == Some(result_index);
                    row.set_selected(is_selected);

                    let result = &self.results[result_index];
                    row.col(|ui| {
                        ui.label(&result.node.name);
                    });
                    row.col(|ui| {
                        ui.label(&result.node.node_type);
                    });
                    row.col(|ui| {
                        ui.label(&result.node.server);
                    });
                    row.col(|ui| {
                        ui.label(result.node.port.to_string());
                    });
                    row.col(|ui| {
                        ui.label(
                            result
                                .tcp_avg_latency_ms
                                .map(|value| format!("{value} ms"))
                                .unwrap_or_else(|| "-".to_owned()),
                        );
                    });
                    row.col(|ui| {
                        ui.label(format!("{}/{}", result.tcp_successes, result.tcp_attempts));
                    });
                    row.col(|ui| {
                        ui.label(
                            result
                                .tcp_jitter_ms
                                .map(|value| format!("{value} ms"))
                                .unwrap_or_else(|| "-".to_owned()),
                        );
                    });
                    row.col(|ui| {
                        ui.label(format!("{:.1}%", result.tcp_loss_percent));
                    });
                    row.col(|ui| {
                        let (udp_text, udp_color) = match &result.udp_status {
                            UdpProbeStatus::Passed(message) => (
                                result
                                    .udp_latency_ms
                                    .map(|latency| format!("通过({message}, {latency}ms)"))
                                    .unwrap_or_else(|| format!("通过({message})")),
                                egui::Color32::from_rgb(32, 145, 91),
                            ),
                            UdpProbeStatus::Partial(message) => (
                                format!("部分({message})"),
                                egui::Color32::from_rgb(194, 122, 0),
                            ),
                            UdpProbeStatus::Failed(message) => (
                                format!("失败({message})"),
                                egui::Color32::from_rgb(190, 64, 64),
                            ),
                            UdpProbeStatus::Skipped(message) => {
                                (format!("跳过({message})"), ui.visuals().weak_text_color())
                            }
                        };
                        let response = ui.colored_label(udp_color, short_text(&udp_text, 30));
                        response.on_hover_text(udp_text);
                    });
                    row.col(|ui| {
                        let (ttfb_text, ttfb_color) = match &result.ttfb_status {
                            TtfbProbeStatus::Passed(message) => (
                                result
                                    .ttfb_ms
                                    .map(|latency| format!("通过({message}, {latency}ms)"))
                                    .unwrap_or_else(|| format!("通过({message})")),
                                egui::Color32::from_rgb(32, 145, 91),
                            ),
                            TtfbProbeStatus::Failed(message) => (
                                format!("失败({message})"),
                                egui::Color32::from_rgb(190, 64, 64),
                            ),
                            TtfbProbeStatus::Skipped(message) => {
                                (format!("跳过({message})"), ui.visuals().weak_text_color())
                            }
                        };
                        let response = ui.colored_label(ttfb_color, short_text(&ttfb_text, 30));
                        response.on_hover_text(ttfb_text);
                    });
                    row.col(|ui| {
                        let (stability_text, stability_color) = match result.stability.level {
                            StabilityLevel::High => (
                                format!("高 ({:.1}%超时)", result.stability.timeout_rate_percent),
                                egui::Color32::from_rgb(32, 145, 91),
                            ),
                            StabilityLevel::Medium => (
                                format!("中 ({:.1}%超时)", result.stability.timeout_rate_percent),
                                egui::Color32::from_rgb(194, 122, 0),
                            ),
                            StabilityLevel::Low => (
                                format!("低 ({:.1}%超时)", result.stability.timeout_rate_percent),
                                egui::Color32::from_rgb(190, 64, 64),
                            ),
                            StabilityLevel::Disabled => {
                                ("关闭".to_owned(), ui.visuals().weak_text_color())
                            }
                        };
                        let response =
                            ui.colored_label(stability_color, short_text(&stability_text, 24));
                        response.on_hover_text(format!(
                            "窗口: {} 秒\n采样: {}\n失败: {}\n最大连续失败: {}",
                            result.stability.window_secs,
                            result.stability.samples,
                            result.stability.failures,
                            result.stability.max_consecutive_failures
                        ));
                    });
                    row.col(|ui| {
                        let (probe_text, probe_color) = match &result.protocol_probe {
                            ProtocolProbeStatus::Passed(message) => (
                                format!("通过({message})"),
                                egui::Color32::from_rgb(32, 145, 91),
                            ),
                            ProtocolProbeStatus::Partial(message) => (
                                format!("部分({message})"),
                                egui::Color32::from_rgb(194, 122, 0),
                            ),
                            ProtocolProbeStatus::Failed(message) => (
                                format!("失败({message})"),
                                egui::Color32::from_rgb(190, 64, 64),
                            ),
                            ProtocolProbeStatus::Skipped(message) => {
                                (format!("跳过({message})"), ui.visuals().weak_text_color())
                            }
                        };
                        let response = ui.colored_label(probe_color, short_text(&probe_text, 30));
                        response.on_hover_text(probe_text);
                    });
                    row.col(|ui| {
                        let (tls_text, tls_color) = match &result.tls_status {
                            TlsProbeStatus::Passed => (
                                result
                                    .tls_latency_ms
                                    .map(|latency| format!("通过 {latency}ms"))
                                    .unwrap_or_else(|| "通过".to_owned()),
                                egui::Color32::from_rgb(32, 145, 91),
                            ),
                            TlsProbeStatus::Disabled => {
                                ("关闭".to_owned(), ui.visuals().weak_text_color())
                            }
                            TlsProbeStatus::Skipped(reason) => {
                                (format!("跳过({reason})"), ui.visuals().weak_text_color())
                            }
                            TlsProbeStatus::Failed(reason) => (
                                format!("失败({reason})"),
                                egui::Color32::from_rgb(190, 64, 64),
                            ),
                        };
                        let response = ui.colored_label(tls_color, short_text(&tls_text, 42));
                        response.on_hover_text(tls_text);
                    });
                    row.col(|ui| {
                        let (security_text, security_color) = match result.security.security_level {
                            SecurityLevel::High => ("高", egui::Color32::from_rgb(32, 145, 91)),
                            SecurityLevel::Medium => ("中", egui::Color32::from_rgb(194, 122, 0)),
                            SecurityLevel::Low => ("低", egui::Color32::from_rgb(190, 64, 64)),
                            SecurityLevel::Unknown => ("未知", ui.visuals().weak_text_color()),
                        };
                        let response = ui.colored_label(security_color, security_text);
                        response.on_hover_text(if result.security.security_reason.is_empty() {
                            format!("安全等级: {}", result.security.security_level.label())
                        } else {
                            format!(
                                "安全等级: {}\n{}",
                                result.security.security_level.label(),
                                result.security.security_reason
                            )
                        });
                    });
                    row.col(|ui| {
                        let (enc_text, enc_color) = match result.security.encryption_level {
                            EncryptionLevel::Strong => ("强", egui::Color32::from_rgb(32, 145, 91)),
                            EncryptionLevel::Moderate => {
                                ("中", egui::Color32::from_rgb(194, 122, 0))
                            }
                            EncryptionLevel::Weak => ("弱", egui::Color32::from_rgb(190, 64, 64)),
                            EncryptionLevel::Plaintext => {
                                ("明文", egui::Color32::from_rgb(190, 64, 64))
                            }
                            EncryptionLevel::Unknown => ("未知", ui.visuals().weak_text_color()),
                        };
                        let response = ui.colored_label(enc_color, enc_text);
                        response.on_hover_text(if result.security.encryption_reason.is_empty() {
                            format!("加密等级: {}", result.security.encryption_level.label())
                        } else {
                            format!(
                                "加密等级: {}\n{}",
                                result.security.encryption_level.label(),
                                result.security.encryption_reason
                            )
                        });
                    });
                    row.col(|ui| {
                        ui.label(format!("{} / 100", result.security.score));
                    });
                    row.col(|ui| {
                        let color = match result.status {
                            NodeStatus::Pass => egui::Color32::from_rgb(32, 145, 91),
                            NodeStatus::Warn => egui::Color32::from_rgb(194, 122, 0),
                            NodeStatus::Fail => egui::Color32::from_rgb(190, 64, 64),
                        };
                        let full = format!("{} - {}", result.status.label(), result.message);
                        let response = ui.label(RichText::new(short_text(&full, 56)).color(color));
                        response.on_hover_text(full);
                    });

                    let row_response = row.response();
                    if row_response.clicked() {
                        self.selected_result_index = Some(result_index);
                    }
                    if row_response.double_clicked() {
                        self.selected_result_index = Some(result_index);
                        self.show_node_detail = true;
                    }
                });
            });
    }

    fn control_column_ui(
        &mut self,
        ui: &mut egui::Ui,
        include_results_between_primary_and_filter: bool,
    ) {
        let filtered_count = self.filtered_result_indices().len();
        let subscription_score = self.subscription_score_summary();
        let privacy_reason = if self.start_summary.local_privacy.reason.trim().is_empty() {
            "等待检测完成后生成本机私流安全评估。".to_owned()
        } else {
            self.start_summary.local_privacy.reason.clone()
        };
        let privacy_color = match self.start_summary.local_privacy.level {
            SecurityLevel::High => egui::Color32::from_rgb(32, 145, 91),
            SecurityLevel::Medium => egui::Color32::from_rgb(194, 122, 0),
            SecurityLevel::Low => egui::Color32::from_rgb(190, 64, 64),
            SecurityLevel::Unknown => ui.visuals().weak_text_color(),
        };
        let status_color = if self.checking {
            egui::Color32::from_rgb(58, 110, 165)
        } else {
            ui.visuals().weak_text_color()
        };

        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                panel_card(
                    ui,
                    "检测控制",
                    Some("输入订阅地址并配置本次探测参数"),
                    |ui| {
                        ui.label("订阅 URL");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.subscription_url)
                                .desired_width(f32::INFINITY)
                                .hint_text("https://example.com/clash.yaml"),
                        );
                        ui.add_space(10.0);

                        ui.label(RichText::new("检测参数").strong());
                        ui.add_space(6.0);
                        egui::Grid::new("control_grid")
                            .num_columns(2)
                            .spacing([10.0, 8.0])
                            .show(ui, |ui| {
                                ui.label("超时");
                                ui.add(
                                    egui::Slider::new(&mut self.timeout_secs, 1.0..=20.0)
                                        .suffix(" 秒")
                                        .step_by(1.0),
                                );
                                ui.end_row();

                                ui.label("采样次数");
                                ui.add(
                                    egui::Slider::new(&mut self.attempts, 1..=10).suffix(" 次"),
                                );
                                ui.end_row();

                                ui.label("并发");
                                ui.add(
                                    egui::Slider::new(&mut self.workers, 1..=128)
                                        .suffix(" 线程"),
                                );
                                ui.end_row();
                            });

                        ui.add_space(6.0);
                        ui.horizontal_wrapped(|ui| {
                            ui.checkbox(&mut self.enable_tls_probe, "TLS 握手检测");
                            ui.label("稳定性窗口");
                            ui.selectable_value(&mut self.stability_window_secs, 0, "关闭");
                            ui.selectable_value(&mut self.stability_window_secs, 30, "30秒");
                            ui.selectable_value(&mut self.stability_window_secs, 60, "60秒");
                        });

                        ui.add_space(10.0);
                        let button_text = if self.checking {
                            "检测中..."
                        } else {
                            "开始检测"
                        };
                        if ui
                            .add_sized([ui.available_width(), 34.0], egui::Button::new(button_text))
                            .clicked()
                            && !self.checking
                        {
                            self.start();
                        }

                        ui.add_space(8.0);
                        ui.add(
                            egui::Label::new(
                                RichText::new(&self.status_line)
                                    .small()
                                    .color(status_color),
                            )
                            .wrap(),
                        );
                    },
                );

                ui.add_space(10.0);
                if include_results_between_primary_and_filter {
                    self.results_workspace_ui(ui);
                    ui.add_space(10.0);
                }

                panel_card(
                    ui,
                    "筛选与搜索",
                    Some("按状态过滤结果，并按节点名、服务器或失败原因搜索"),
                    |ui| {
                        ui.horizontal_wrapped(|ui| {
                            ui.selectable_value(&mut self.row_filter, RowFilter::All, "全部");
                            ui.selectable_value(&mut self.row_filter, RowFilter::Pass, "通过");
                            ui.selectable_value(&mut self.row_filter, RowFilter::Warn, "部分");
                            ui.selectable_value(&mut self.row_filter, RowFilter::Fail, "失败");
                            ui.selectable_value(
                                &mut self.row_filter,
                                RowFilter::HighRisk,
                                "高风险",
                            );
                        });
                        ui.add_space(6.0);
                        ui.add(
                            egui::TextEdit::singleline(&mut self.search_text)
                                .desired_width(f32::INFINITY)
                                .hint_text("节点名 / 服务器 / 原因"),
                        );
                    },
                );

                ui.add_space(10.0);
                panel_card(
                    ui,
                    "订阅概览",
                    Some("综合评分、本机私流与关键指标"),
                    |ui| {
                        let overview_items = [
                            (
                                "综合评分",
                                format!(
                                    "{} / 100 ({})",
                                    subscription_score.score, subscription_score.grade
                                ),
                            ),
                            (
                                "本机私流",
                                format!(
                                    "{}（启发式）",
                                    self.start_summary.local_privacy.level.label()
                                ),
                            ),
                            ("当前显示", format!("{} / {}", filtered_count, self.results.len())),
                        ];
                        summary_tile_grid(ui, &overview_items);
                        ui.add_space(8.0);

                        ui.label(RichText::new("快速指标").strong());
                        ui.add_space(6.0);
                        ui.horizontal_wrapped(|ui| {
                            metric_chip(ui, "TCP可连", &self.tcp_alive_count().to_string());
                            metric_chip(ui, "UDP通过", &self.udp_pass_count().to_string());
                            metric_chip(ui, "TTFB通过", &self.ttfb_pass_count().to_string());
                            metric_chip(ui, "严格通过", &self.pass_count().to_string());
                            metric_chip(ui, "失败", &self.fail_count().to_string());
                            let privacy_response = metric_chip(
                                ui,
                                "本机私流",
                                self.start_summary.local_privacy.level.label(),
                            );
                            privacy_response.on_hover_text(privacy_reason.clone());
                            let response = metric_chip(
                                ui,
                                "综合评分",
                                &format!("{} / 100", subscription_score.score),
                            );
                            response.on_hover_text(format!(
                                "订阅评级: {}\n{}",
                                subscription_score.grade,
                                subscription_score.note
                            ));
                        });

                        ui.add_space(8.0);
                        egui::Frame::group(ui.style())
                            .inner_margin(egui::Margin::same(10.0))
                            .show(ui, |ui| {
                                ui.horizontal_wrapped(|ui| {
                                    ui.label(RichText::new("本机私流安全").strong());
                                    ui.colored_label(
                                        privacy_color,
                                        self.start_summary.local_privacy.level.label(),
                                    );
                                    ui.small("订阅级启发式评估");
                                });
                                ui.add_space(4.0);
                                ui.add(egui::Label::new(privacy_reason).wrap());
                            });

                        ui.add_space(8.0);
                        egui::CollapsingHeader::new("展开完整指标面板")
                            .default_open(false)
                            .show(ui, |ui| {
                                self.summary_ui(ui);
                            });
                    },
                );

                ui.add_space(10.0);
                self.version_update_card_ui(ui);

                if let Some(result) = self
                    .selected_result_index
                    .and_then(|index| self.results.get(index))
                {
                    ui.add_space(10.0);
                    panel_card(
                        ui,
                        "当前选中节点",
                        Some("从右侧结果表单击节点后，这里会同步显示摘要"),
                        |ui| {
                            ui.strong(&result.node.name);
                            ui.add_space(4.0);
                            ui.label(format!(
                                "端点：{}:{}  |  协议：{}",
                                result.node.server, result.node.port, result.node.node_type
                            ));
                            ui.label(format!(
                                "完整状态：{} - {}",
                                result.status.label(),
                                result.message
                            ));
                            if !result.security.note.is_empty() {
                                ui.add_space(4.0);
                                ui.label(format!("评估说明：{}", result.security.note));
                            }
                        },
                    );
                }
            });
    }

    fn results_workspace_ui(&mut self, ui: &mut egui::Ui) {
        let filtered_indices = self.filtered_result_indices();
        let display_text = format!("{} / {}", filtered_indices.len(), self.results.len());
        let selected_label = self
            .selected_result_index
            .and_then(|index| self.results.get(index))
            .map(|result| format!("当前选中：{}", result.node.name));

        panel_card(
            ui,
            "节点结果",
            Some("单击行选中，双击行打开节点详细信息；结果区默认显示约 20 行，可上下滚动查看更多"),
            |ui| {
                ui.horizontal_wrapped(|ui| {
                    metric_chip(ui, "显示", &display_text);
                    ui.label(RichText::new("表格模式").weak());
                    ui.selectable_value(&mut self.table_mode, TableMode::Compact, "精简");
                    ui.selectable_value(&mut self.table_mode, TableMode::Full, "完整");
                    if ui.button("打开详情").clicked() && self.selected_result_index.is_some() {
                        self.show_node_detail = true;
                    }
                    if let Some(selected_label) = &selected_label {
                        ui.label(RichText::new(selected_label).weak());
                    }
                });
                ui.add_space(8.0);

                egui::Frame::group(ui.style())
                    .fill(ui.visuals().faint_bg_color)
                    .inner_margin(egui::Margin::same(8.0))
                    .show(ui, |ui| {
                        ui.set_min_height(result_table_scroll_height() + 24.0);
                        if self.results.is_empty() {
                            result_empty_state(
                                ui,
                                "还没有检测结果",
                                "在左侧输入订阅地址并点击“开始检测”，完成后这里会显示节点列表、状态和详细指标。",
                            );
                        } else if filtered_indices.is_empty() {
                            result_empty_state(
                                ui,
                                "当前筛选条件没有匹配结果",
                                "可以切换筛选按钮，或清空搜索框后重新查看全部节点。",
                            );
                        } else {
                            let min_width = match self.table_mode {
                                TableMode::Compact => 1850.0,
                                TableMode::Full => 3650.0,
                            };
                            egui::ScrollArea::horizontal()
                                .auto_shrink([false, false])
                                .show(ui, |ui| {
                                    ui.set_min_width(min_width);
                                    self.table_ui(ui, &filtered_indices);
                                });
                        }
                    });
            },
        );
    }
}

impl eframe::App for ClashCheckerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_events();

        if self.checking || self.update_rx.is_some() {
            ctx.request_repaint_after(Duration::from_millis(100));
        }

        egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("说明", |ui| {
                    if ui.button("指标说明").clicked() {
                        self.show_metric_guide = true;
                        ui.close_menu();
                    }
                    if ui.button("状态颜色说明").clicked() {
                        self.show_metric_guide = true;
                        ui.close_menu();
                    }
                });
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            let run_state = if self.checking {
                ("检测进行中", egui::Color32::from_rgb(58, 110, 165))
            } else if self.results.is_empty() {
                ("准备就绪", ui.visuals().weak_text_color())
            } else {
                ("检测完成", egui::Color32::from_rgb(32, 145, 91))
            };

            ui.horizontal_wrapped(|ui| {
                ui.heading("Clash 订阅节点多项检测");
                ui.label(RichText::new(format!("v{}", update::current_version())).weak());
                ui.colored_label(run_state.1, run_state.0);
            });
            ui.label(
                RichText::new("宽窗口下左侧负责检测控制、筛选与订阅概览，右侧负责结果工作区；窄窗口下节点结果会放在检测控制与筛选之间。")
                    .weak(),
            );
            ui.add(
                egui::Label::new(
                    RichText::new("测试结果的优劣由您的本地网络环境直接关联，本程序最初目的也是测试某一订阅在当前网络环境下的优劣，推荐您购买各家代理服务商的最基础套餐进行测试。")
                        .small()
                        .weak(),
                )
                .wrap(),
            );
            ui.add_space(10.0);

            let available_width = ui.available_width();
            let available_height = ui.available_height();
            let spacing = 12.0;

            if available_width < 980.0 {
                self.control_column_ui(ui, true);
            } else {
                let left_width = (available_width * 0.38)
                    .clamp(360.0, 500.0)
                    .min(available_width - spacing - 320.0);
                let right_width = (available_width - left_width - spacing).max(320.0);

                ui.horizontal_top(|ui| {
                    ui.allocate_ui_with_layout(
                        egui::vec2(left_width, available_height),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| {
                            self.control_column_ui(ui, false);
                        },
                    );
                    ui.add_space(spacing);
                    ui.allocate_ui_with_layout(
                        egui::vec2(right_width, available_height),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| {
                            self.results_workspace_ui(ui);
                        },
                    );
                });
            }
        });
        if self.show_metric_guide {
            let viewport_rect = ctx.screen_rect();
            let guide_default_width = (viewport_rect.width() * 0.72).clamp(420.0, 920.0);
            let guide_default_height = (viewport_rect.height() * 0.82).clamp(320.0, 860.0);
            let guide_max_width = (viewport_rect.width() - 32.0).max(360.0);
            let guide_max_height = (viewport_rect.height() - 32.0).max(280.0);

            egui::Window::new("指标说明")
                .open(&mut self.show_metric_guide)
                .resizable(true)
                .default_size([guide_default_width, guide_default_height])
                .min_size([360.0, 260.0])
                .max_size([guide_max_width, guide_max_height])
                .show(ctx, |ui| {
                    egui::ScrollArea::vertical()
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            ui.heading("结果怎么读");
                            ui.label("总节点：本次解析到的节点数量。");
                            ui.label("TCP可连：至少一次 TCP 连接成功的节点数。");
                            ui.label("严格通过：TCP 采样全部成功，且 TLS 预检通过。");
                            ui.label(
                                "部分通过：TCP 可连，但未达到严格通过（比如 TLS 失败或采样非全成功）。",
                            );
                            ui.label("失败：DNS 无法解析或 TCP 全部失败。");
                            ui.add_space(8.0);

                            ui.heading("各列含义");
                            ui.label("TCP均延迟：TCP 成功采样的平均耗时。");
                            ui.label("TCP成功：采样成功次数 / 采样总次数。");
                            ui.label("抖动：成功采样之间的延迟波动（相邻差值平均）。");
                            ui.label("丢包：TCP 采样失败占比。");
                            ui.label("UDP：UDP 可达性探测结果（通过/部分/失败/跳过）。");
                            ui.label("TTFB：首包时间探测。trojan/vless 已支持通过代理链访问测试 URL 的 HTTP 首包；其中 VLESS REALITY/XTLS 当前会跳过，避免复用普通 TLS 基线误判；其余协议仍以 TLS/HTTP 首包基线实现。");
                            ui.label("稳定性：在 30/60 秒窗口内统计超时率与连续失败次数。");
                            ui.label("协议探测：trojan/vless、vmess TCP AEAD、hysteria2 已接入真实路径；tuic/hysteria 当前为 QUIC 连接尝试；REALITY/XTLS 当前会识别参数完整度并避免误判为普通 TLS 成功。");
                            ui.label("TLS：对 TLS 类协议执行 ClientHello 预检的结果；当前不等同于证书链、到期时间、域名匹配的完整审计。");
                            ui.label("安全：综合协议、TLS、证书校验策略、稳定性、GFW通过性/防追踪/现网稳定性画像与本地网络可达性得出的安全等级。");
                            ui.label("加密：根据协议和可见配置推断的加密强度。");
                            ui.label("GFW通过性：根据 TLS/REALITY、SNI、ALPN 与传输伪装评估穿透 GFW 的适配度。");
                            ui.label("防追踪：根据加密强度、证书校验、SNI/ALPN 完整性评估侧写风险。");
                            ui.label("本地网络可达性：根据当前本地网络下的 TCP 成功率、丢包、抖动、TTFB、UDP 与稳定性窗口计算 0~100 分。");
                            ui.label("现网稳定性：综合持续稳定性窗口、TTFB、丢包、抖动与 GFW/防追踪特征估计。");
                            ui.label("本机私流：优先基于订阅 YAML 的 DNS、规则、TUN、控制口与局域网暴露配置评估本机流量泄露风险；若只有节点列表，则退化为启发式估计，当前未执行真实 DNS 泄露请求或抓包。");
                            ui.label("评分：节点表中的评分是单节点安全分；左侧“订阅综合”是按可用性、安全性、传输质量、现网稳定性和订阅整洁度聚合的订阅分。");
                            ui.label("状态：将 DNS/TCP/TLS 汇总后的最终判定与简要原因。");
                            ui.add_space(8.0);

                            ui.heading("筛选与搜索");
                            ui.label("结果筛选：按通过/部分/失败/高风险快速过滤。");
                            ui.label("搜索框：支持节点名、服务器、失败原因关键字匹配。");
                            ui.label("节点结果卡片默认显示约 20 行，可在卡片内部上下滚动查看更多节点。");
                            ui.add_space(8.0);

                            ui.heading("详情查看");
                            ui.label("双击列表任意节点，可打开“节点详细信息”窗口。");
                            ui.label("详细信息里会显示协议参数、TLS状态、安全等级、评分与评估说明。");
                            ui.label("协议探测=跳过：通常表示该协议真实握手将在后续版本补齐。");
                            ui.label("TTFB=跳过：代表该协议暂未定义可比首包探测方式。");
                            ui.add_space(8.0);

                            ui.heading("当前版本边界");
                            ui.label("当前仍未补齐 tuic/hysteria 的应用层认证，以及 REALITY/XTLS 专用客户端路径；vmess TCP AEAD 与 hysteria2 应用层认证已接入。");
                            ui.label("证书链、到期时间、域名匹配、自签状态、TLS 版本与握手失败子类型当前尚未输出。");
                            ui.label("DNS 泄露与本机私网流量当前未做真实请求或抓包，只做启发式评估。");
                            ui.label("吞吐测试、出口 IP/ASN/地区、IPv4/IPv6、业务场景可达性当前尚未接入。");
                            ui.add_space(8.0);

                            ui.heading("常见疑问");
                            ui.label("测试结果的优劣由您的本地网络环境直接关联，本程序最初目的也是测试某一订阅在当前网络环境下的优劣，推荐您购买各家代理服务商的最基础套餐进行测试。");
                            ui.label("“TLS 失败 (failed to fill whole buffer)” 通常不代表订阅链接有问题。");
                            ui.label("这更常见于节点服务端策略或预检方式兼容性导致的握手未返回完整响应。");
                            ui.label("如果 TCP 持续 3/3 成功，这个节点在真实客户端里仍可能可用。");
                            ui.add_space(8.0);

                            ui.heading("状态颜色");
                            ui.label("绿色：通过（指标整体健康）。");
                            ui.label("橙色：部分通过（有风险项，建议复测）。");
                            ui.label("红色：失败（当前检测项不通过）。");
                        });
                });
        }

        if self.show_node_detail {
            let selected = self
                .selected_result_index
                .and_then(|index| self.results.get(index).cloned());
            egui::Window::new("节点详细信息")
                .open(&mut self.show_node_detail)
                .collapsible(false)
                .resizable(true)
                .default_size([980.0, 760.0])
                .min_size([720.0, 520.0])
                .show(ctx, |ui| {
                    let Some(result) = selected else {
                        ui.label("当前没有可查看的节点详情。");
                        return;
                    };

                    egui::ScrollArea::vertical()
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            ui.heading(&result.node.name);
                            ui.add_space(8.0);

                            egui::Grid::new("node_detail_grid")
                                .num_columns(2)
                                .striped(true)
                                .spacing([12.0, 8.0])
                                .show(ui, |ui| {
                                    detail_row(ui, "协议", &result.node.node_type);
                                    detail_row(ui, "服务器", &result.node.server);
                                    detail_row(ui, "端口", &result.node.port.to_string());
                                    detail_row(
                                        ui,
                                        "TCP成功",
                                        &format!(
                                            "{}/{}",
                                            result.tcp_successes, result.tcp_attempts
                                        ),
                                    );
                                    detail_row(
                                        ui,
                                        "TCP均延迟",
                                        &result
                                            .tcp_avg_latency_ms
                                            .map(|value| format!("{value} ms"))
                                            .unwrap_or_else(|| "-".to_owned()),
                                    );
                                    detail_row(
                                        ui,
                                        "TCP抖动",
                                        &result
                                            .tcp_jitter_ms
                                            .map(|value| format!("{value} ms"))
                                            .unwrap_or_else(|| "-".to_owned()),
                                    );
                                    detail_row(
                                        ui,
                                        "TCP丢包",
                                        &format!("{:.1}%", result.tcp_loss_percent),
                                    );
                                    detail_row(
                                        ui,
                                        "TLS结果",
                                        &match &result.tls_status {
                                            TlsProbeStatus::Passed => result
                                                .tls_latency_ms
                                                .map(|latency| format!("通过 ({latency} ms)"))
                                                .unwrap_or_else(|| "通过".to_owned()),
                                            TlsProbeStatus::Disabled => "关闭".to_owned(),
                                            TlsProbeStatus::Skipped(reason) => {
                                                format!("跳过 ({reason})")
                                            }
                                            TlsProbeStatus::Failed(reason) => {
                                                format!("失败 ({reason})")
                                            }
                                        },
                                    );
                                    detail_row(
                                        ui,
                                        "UDP结果",
                                        &match &result.udp_status {
                                            UdpProbeStatus::Passed(reason) => result
                                                .udp_latency_ms
                                                .map(|latency| {
                                                    format!("通过 ({reason}, {latency} ms)")
                                                })
                                                .unwrap_or_else(|| format!("通过 ({reason})")),
                                            UdpProbeStatus::Partial(reason) => {
                                                format!("部分 ({reason})")
                                            }
                                            UdpProbeStatus::Failed(reason) => {
                                                format!("失败 ({reason})")
                                            }
                                            UdpProbeStatus::Skipped(reason) => {
                                                format!("跳过 ({reason})")
                                            }
                                        },
                                    );
                                    detail_row(
                                        ui,
                                        "TTFB结果",
                                        &match &result.ttfb_status {
                                            TtfbProbeStatus::Passed(reason) => result
                                                .ttfb_ms
                                                .map(|latency| {
                                                    format!("通过 ({reason}, {latency} ms)")
                                                })
                                                .unwrap_or_else(|| format!("通过 ({reason})")),
                                            TtfbProbeStatus::Failed(reason) => {
                                                format!("失败 ({reason})")
                                            }
                                            TtfbProbeStatus::Skipped(reason) => {
                                                format!("跳过 ({reason})")
                                            }
                                        },
                                    );
                                    detail_row(
                                        ui,
                                        "稳定性",
                                        &if result.stability.level == StabilityLevel::Disabled {
                                            "关闭".to_owned()
                                        } else {
                                            format!(
                                                "{}（窗口 {} 秒，超时率 {:.1}%，最大连续失败 {}）",
                                                result.stability.level.label(),
                                                result.stability.window_secs,
                                                result.stability.timeout_rate_percent,
                                                result.stability.max_consecutive_failures
                                            )
                                        },
                                    );
                                    detail_row(
                                        ui,
                                        "协议探测",
                                        &result.protocol_probe.short_label(),
                                    );
                                    detail_row(
                                        ui,
                                        "安全等级",
                                        &format!(
                                            "{} | {}",
                                            result.security.security_level.label(),
                                            result.security.security_reason
                                        ),
                                    );
                                    detail_row(
                                        ui,
                                        "加密等级",
                                        &format!(
                                            "{} | {}",
                                            result.security.encryption_level.label(),
                                            result.security.encryption_reason
                                        ),
                                    );
                                    detail_row(
                                        ui,
                                        "现网稳定性",
                                        &format!(
                                            "{} | {}",
                                            result.security.live_network_level.label(),
                                            result.security.live_network_reason
                                        ),
                                    );
                                    detail_row(
                                        ui,
                                        "本地网络可达性",
                                        &format!(
                                            "{} | {} 分 | {}",
                                            result.security.local_network_level.label(),
                                            result.security.local_network_score,
                                            result.security.local_network_reason
                                        ),
                                    );
                                    detail_row(
                                        ui,
                                        "GFW通过性",
                                        &format!(
                                            "{} | {} 分 | {}",
                                            result.security.gfw_level.label(),
                                            result.security.gfw_score,
                                            result.security.gfw_reason
                                        ),
                                    );
                                    detail_row(
                                        ui,
                                        "防追踪",
                                        &format!(
                                            "{} | {}",
                                            result.security.anti_tracking_level.label(),
                                            result.security.anti_tracking_reason
                                        ),
                                    );
                                    detail_row(
                                        ui,
                                        "安全评分",
                                        &format!("{} / 100", result.security.score),
                                    );
                                    detail_row(ui, "TLS配置", &option_bool_text(result.node.tls));
                                    detail_row(
                                        ui,
                                        "跳过证书校验",
                                        &option_bool_text(result.node.skip_cert_verify),
                                    );
                                    detail_row(
                                        ui,
                                        "Cipher",
                                        &option_text(result.node.cipher.as_deref()),
                                    );
                                    detail_row(
                                        ui,
                                        "Security",
                                        &option_text(result.node.security.as_deref()),
                                    );
                                    detail_row(
                                        ui,
                                        "Flow",
                                        &option_text(result.node.flow.as_deref()),
                                    );
                                    detail_row(
                                        ui,
                                        "ALPN",
                                        &option_text(result.node.alpn.as_deref()),
                                    );
                                    detail_row(
                                        ui,
                                        "Network",
                                        &option_text(result.node.network.as_deref()),
                                    );
                                    detail_row(
                                        ui,
                                        "ServerName/SNI",
                                        &option_text(result.node.server_name.as_deref()),
                                    );
                                    detail_row(ui, "最终状态", result.status.label());
                                });

                            ui.add_space(8.0);
                            ui.label("评估说明");
                            ui.separator();
                            ui.label(if result.security.note.is_empty() {
                                "无额外说明".to_owned()
                            } else {
                                result.security.note
                            });
                            ui.add_space(8.0);
                            ui.label(format!("检测摘要：{}", result.message));
                        });
                });
        }
    }
}

struct SubscriptionAggregateScore {
    score: u8,
    grade: &'static str,
    note: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RowFilter {
    All,
    Pass,
    Warn,
    Fail,
    HighRisk,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TableMode {
    Compact,
    Full,
}

fn configure_chinese_font(ctx: &egui::Context) {
    let candidates = [
        r"C:\Windows\Fonts\simhei.ttf",
        r"C:\Windows\Fonts\msyh.ttc",
        r"C:\Windows\Fonts\simsun.ttc",
    ];

    let Some(font_bytes) = candidates.iter().find_map(|path| fs::read(path).ok()) else {
        return;
    };

    let font_name = "system_chinese".to_owned();
    let mut fonts = egui::FontDefinitions::default();
    fonts
        .font_data
        .insert(font_name.clone(), egui::FontData::from_owned(font_bytes));

    for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
        fonts
            .families
            .entry(family)
            .or_default()
            .insert(0, font_name.clone());
    }

    ctx.set_fonts(fonts);
}

fn compute_subscription_score(
    results: &[NodeCheckResult],
    start_summary: &StartSummary,
) -> SubscriptionAggregateScore {
    if results.is_empty() {
        return SubscriptionAggregateScore {
            score: 0,
            grade: "待检测",
            note: "等待节点检测完成后，按可用性、安全性、传输质量、现网稳定性和订阅整洁度计算综合评分。"
                .to_owned(),
        };
    }

    let total = results.len() as f32;
    let dns_rate = results.iter().filter(|result| result.dns_ok).count() as f32 / total;
    let tcp_rate = results.iter().filter(|result| result.tcp_alive()).count() as f32 / total;
    let strict_rate = results
        .iter()
        .filter(|result| result.status == NodeStatus::Pass)
        .count() as f32
        / total;
    let availability_points = score_points(
        dns_rate * 0.25 + tcp_rate * 0.35 + strict_rate * 0.40,
        35,
    );

    let avg_security_score = results
        .iter()
        .map(|result| result.security.score as f32)
        .sum::<f32>()
        / total;
    let security_points = score_points(avg_security_score / 100.0, 25);

    let tls_ratio = if start_summary.tls_target_count == 0 {
        1.0
    } else {
        results
            .iter()
            .filter(|result| result.tls_status.is_passed())
            .count() as f32
            / start_summary.tls_target_count as f32
    };
    let protocol_ratio = results
        .iter()
        .map(|result| protocol_probe_ratio(&result.protocol_probe))
        .sum::<f32>()
        / total;
    let udp_ratio = results
        .iter()
        .map(|result| udp_probe_ratio(&result.udp_status))
        .sum::<f32>()
        / total;
    let ttfb_ratio = results
        .iter()
        .map(|result| ttfb_probe_ratio(&result.ttfb_status))
        .sum::<f32>()
        / total;
    let transport_points = score_points(
        protocol_ratio * 0.35 + tls_ratio * 0.25 + udp_ratio * 0.20 + ttfb_ratio * 0.20,
        20,
    );

    let live_network_ratio = results
        .iter()
        .map(|result| security_level_ratio(&result.security.live_network_level))
        .sum::<f32>()
        / total;
    let stability_points = score_points(live_network_ratio * 0.75 + strict_rate * 0.25, 15);

    let unique_endpoint_ratio = if start_summary.total == 0 {
        1.0
    } else {
        start_summary.unique_endpoints as f32 / start_summary.total as f32
    };
    let unique_name_ratio = if start_summary.total == 0 {
        1.0
    } else {
        (start_summary.total.saturating_sub(start_summary.duplicate_names)) as f32
            / start_summary.total as f32
    };
    let hygiene_points = score_points(
        unique_endpoint_ratio * 0.60 + unique_name_ratio * 0.40,
        5,
    );

    let score = availability_points
        .saturating_add(security_points)
        .saturating_add(transport_points)
        .saturating_add(stability_points)
        .saturating_add(hygiene_points)
        .min(100);
    let grade = subscription_grade(score);
    let note = format!(
        "可用性 {availability_points}/35，安全 {security_points}/25，传输 {transport_points}/20，现网稳定 {stability_points}/15，订阅整洁度 {hygiene_points}/5。TCP可连率 {:.1}%，严格通过率 {:.1}%，平均单节点安全分 {:.1}，TLS通过率 {:.1}%，唯一端点率 {:.1}%。",
        tcp_rate * 100.0,
        strict_rate * 100.0,
        avg_security_score,
        tls_ratio * 100.0,
        unique_endpoint_ratio * 100.0,
    );

    SubscriptionAggregateScore { score, grade, note }
}

fn score_points(value: f32, max_points: u8) -> u8 {
    (value.clamp(0.0, 1.0) * max_points as f32).round() as u8
}

fn subscription_grade(score: u8) -> &'static str {
    match score {
        90..=100 => "S",
        80..=89 => "A",
        70..=79 => "B",
        60..=69 => "C",
        _ => "D",
    }
}

fn security_level_ratio(level: &SecurityLevel) -> f32 {
    match level {
        SecurityLevel::High => 1.0,
        SecurityLevel::Medium => 0.72,
        SecurityLevel::Low => 0.35,
        SecurityLevel::Unknown => 0.45,
    }
}

fn protocol_probe_ratio(status: &ProtocolProbeStatus) -> f32 {
    match status {
        ProtocolProbeStatus::Passed(_) => 1.0,
        ProtocolProbeStatus::Partial(_) => 0.65,
        ProtocolProbeStatus::Skipped(_) => 0.75,
        ProtocolProbeStatus::Failed(_) => 0.0,
    }
}

fn udp_probe_ratio(status: &UdpProbeStatus) -> f32 {
    match status {
        UdpProbeStatus::Passed(_) => 1.0,
        UdpProbeStatus::Partial(_) => 0.60,
        UdpProbeStatus::Skipped(_) => 0.75,
        UdpProbeStatus::Failed(_) => 0.0,
    }
}

fn ttfb_probe_ratio(status: &TtfbProbeStatus) -> f32 {
    match status {
        TtfbProbeStatus::Passed(_) => 1.0,
        TtfbProbeStatus::Skipped(_) => 0.75,
        TtfbProbeStatus::Failed(_) => 0.0,
    }
}

fn panel_card(
    ui: &mut egui::Ui,
    title: &str,
    subtitle: Option<&str>,
    add_contents: impl FnOnce(&mut egui::Ui),
) {
    egui::Frame::group(ui.style())
        .inner_margin(egui::Margin::same(12.0))
        .show(ui, |ui| {
            ui.label(RichText::new(title).strong().size(16.0));
            if let Some(subtitle) = subtitle {
                ui.add_space(2.0);
                ui.label(RichText::new(subtitle).small().weak());
            }
            ui.add_space(8.0);
            add_contents(ui);
        });
}

fn result_empty_state(ui: &mut egui::Ui, title: &str, detail: &str) {
    ui.centered_and_justified(|ui| {
        ui.vertical_centered(|ui| {
            ui.label(RichText::new(title).strong().size(20.0));
            ui.add_space(6.0);
            ui.add_sized(
                [ui.available_width().min(420.0), 0.0],
                egui::Label::new(RichText::new(detail).weak()).wrap(),
            );
        });
    });
}

fn result_table_scroll_height() -> f32 {
    20.0 * 28.0 + 8.0
}

fn summary_tile(ui: &mut egui::Ui, label: &str, value: String) {
    egui::Frame::group(ui.style())
        .inner_margin(egui::Margin::symmetric(10.0, 8.0))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.label(RichText::new(label).strong().size(15.0));
            ui.add_space(2.0);
            ui.label(RichText::new(value).size(18.0));
        });
}

fn summary_tile_grid(ui: &mut egui::Ui, items: &[(&str, String)]) {
    let available_width = ui.available_width().max(1.0);
    let columns: usize = if available_width >= 500.0 {
        3
    } else if available_width >= 280.0 {
        2
    } else {
        1
    };
    let spacing = 8.0;
    let tile_width = ((available_width - (columns.saturating_sub(1) as f32 * spacing))
        / columns as f32)
        .max(120.0);

    egui::Grid::new(ui.next_auto_id())
        .num_columns(columns)
        .spacing([spacing, spacing])
        .show(ui, |ui| {
            for (index, (label, value)) in items.iter().enumerate() {
                ui.allocate_ui_with_layout(
                    egui::vec2(tile_width, 0.0),
                    egui::Layout::top_down(egui::Align::Min),
                    |ui| {
                        ui.set_min_width(tile_width);
                        summary_tile(ui, label, value.clone())
                    },
                );

                if (index + 1) % columns == 0 {
                    ui.end_row();
                }
            }

            if !items.len().is_multiple_of(columns) {
                ui.end_row();
            }
        });
}

fn metric_chip(ui: &mut egui::Ui, label: &str, value: &str) -> egui::Response {
    egui::Frame::group(ui.style())
        .inner_margin(egui::Margin::symmetric(8.0, 6.0))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(label);
                ui.strong(value);
            });
        })
        .response
}

fn detail_row(ui: &mut egui::Ui, key: &str, value: &str) {
    ui.strong(key);
    ui.add(egui::Label::new(value).wrap());
    ui.end_row();
}

fn option_text(value: Option<&str>) -> String {
    value.unwrap_or("未知").to_owned()
}

fn option_bool_text(value: Option<bool>) -> String {
    match value {
        Some(true) => "是".to_owned(),
        Some(false) => "否".to_owned(),
        None => "未知".to_owned(),
    }
}

fn short_text(input: &str, max_chars: usize) -> String {
    if input.chars().count() <= max_chars {
        return input.to_owned();
    }

    let mut output = String::with_capacity(max_chars + 1);
    for (index, ch) in input.chars().enumerate() {
        if index >= max_chars {
            break;
        }
        output.push(ch);
    }
    output.push('…');
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checker::{SecurityAssessment, StabilityMetrics};
    use crate::subscription::ProxyNode;

    fn sample_result(
        status: NodeStatus,
        security_score: u8,
        live_network_level: SecurityLevel,
        protocol_probe: ProtocolProbeStatus,
        udp_status: UdpProbeStatus,
        ttfb_status: TtfbProbeStatus,
        tls_status: TlsProbeStatus,
    ) -> NodeCheckResult {
        NodeCheckResult {
            node: ProxyNode {
                name: "demo".to_owned(),
                node_type: "trojan".to_owned(),
                server: "example.com".to_owned(),
                port: 443,
                ..ProxyNode::default()
            },
            status,
            dns_ok: true,
            tcp_successes: 3,
            tcp_attempts: 3,
            tcp_avg_latency_ms: Some(120),
            tcp_jitter_ms: Some(6),
            tcp_loss_percent: 0.0,
            tls_status,
            tls_latency_ms: Some(80),
            udp_status,
            udp_latency_ms: Some(90),
            ttfb_status,
            ttfb_ms: Some(240),
            stability: StabilityMetrics {
                window_secs: 30,
                samples: 30,
                failures: 0,
                timeout_rate_percent: 0.0,
                max_consecutive_failures: 0,
                level: StabilityLevel::High,
            },
            protocol_probe,
            security: SecurityAssessment {
                security_level: SecurityLevel::High,
                encryption_level: EncryptionLevel::Strong,
                score: security_score,
                security_reason: String::new(),
                encryption_reason: String::new(),
                gfw_level: SecurityLevel::High,
                gfw_score: 88,
                gfw_reason: String::new(),
                anti_tracking_level: SecurityLevel::High,
                anti_tracking_reason: String::new(),
                local_network_level: SecurityLevel::High,
                local_network_score: 90,
                local_network_reason: String::new(),
                live_network_level,
                live_network_reason: String::new(),
                note: String::new(),
            },
            message: "ok".to_owned(),
        }
    }

    #[test]
    fn computes_high_score_for_healthy_subscription() {
        let results = vec![
            sample_result(
                NodeStatus::Pass,
                88,
                SecurityLevel::High,
                ProtocolProbeStatus::Passed("ok".to_owned()),
                UdpProbeStatus::Passed("ok".to_owned()),
                TtfbProbeStatus::Passed("ok".to_owned()),
                TlsProbeStatus::Passed,
            ),
            sample_result(
                NodeStatus::Pass,
                84,
                SecurityLevel::High,
                ProtocolProbeStatus::Passed("ok".to_owned()),
                UdpProbeStatus::Passed("ok".to_owned()),
                TtfbProbeStatus::Passed("ok".to_owned()),
                TlsProbeStatus::Passed,
            ),
        ];
        let summary = StartSummary {
            total: 2,
            unique_endpoints: 2,
            duplicate_endpoints: 0,
            duplicate_names: 0,
            tls_target_count: 2,
            local_privacy: Default::default(),
        };

        let aggregate = compute_subscription_score(&results, &summary);

        assert!(aggregate.score >= 80);
        assert!(matches!(aggregate.grade, "S" | "A"));
    }

    #[test]
    fn penalizes_failed_and_duplicate_subscription() {
        let mut weak_result = sample_result(
            NodeStatus::Fail,
            22,
            SecurityLevel::Low,
            ProtocolProbeStatus::Failed("fail".to_owned()),
            UdpProbeStatus::Failed("fail".to_owned()),
            TtfbProbeStatus::Failed("fail".to_owned()),
            TlsProbeStatus::Failed("fail".to_owned()),
        );
        weak_result.dns_ok = false;
        weak_result.tcp_successes = 0;
        weak_result.tcp_loss_percent = 100.0;
        weak_result.tcp_jitter_ms = None;
        weak_result.security.gfw_level = SecurityLevel::Low;
        weak_result.security.gfw_score = 28;
        weak_result.security.local_network_level = SecurityLevel::Low;
        weak_result.security.local_network_score = 25;
        weak_result.security.anti_tracking_level = SecurityLevel::Low;

        let summary = StartSummary {
            total: 2,
            unique_endpoints: 1,
            duplicate_endpoints: 1,
            duplicate_names: 1,
            tls_target_count: 2,
            local_privacy: Default::default(),
        };
        let aggregate = compute_subscription_score(&[weak_result.clone(), weak_result], &summary);

        assert!(aggregate.score <= 40);
        assert_eq!(aggregate.grade, "D");
    }
}
