use std::fs;
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use eframe::egui;
use egui::RichText;
use egui_extras::{Column, TableBuilder};

use crate::checker::{
    start_check, CheckEvent, CheckOptions, EncryptionLevel, NodeCheckResult, NodeStatus,
    SecurityLevel, StartSummary, TlsProbeStatus,
};

pub struct ClashCheckerApp {
    subscription_url: String,
    timeout_secs: f32,
    attempts: u32,
    workers: u32,
    enable_tls_probe: bool,
    search_text: String,
    row_filter: RowFilter,
    checking: bool,
    show_metric_guide: bool,
    show_node_detail: bool,
    selected_result_index: Option<usize>,
    status_line: String,
    start_summary: StartSummary,
    results: Vec<NodeCheckResult>,
    rx: Option<Receiver<CheckEvent>>,
}

impl ClashCheckerApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        configure_chinese_font(&cc.egui_ctx);

        Self {
            subscription_url: String::new(),
            timeout_secs: 5.0,
            attempts: 3,
            workers: 24,
            enable_tls_probe: true,
            search_text: String::new(),
            row_filter: RowFilter::All,
            checking: false,
            show_metric_guide: false,
            show_node_detail: false,
            selected_result_index: None,
            status_line: "输入 Clash 订阅地址后开始检测".to_owned(),
            start_summary: StartSummary::default(),
            results: Vec::new(),
            rx: None,
        }
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
                            "已检测 {checked}/{} | TCP可连 {} | 严格通过 {} | 失败 {}",
                            self.start_summary.total.max(checked),
                            self.tcp_alive_count(),
                            self.pass_count(),
                            self.fail_count()
                        );
                    }
                    CheckEvent::Finished => {
                        self.checking = false;
                        self.status_line = format!(
                            "检测完成：共 {} 个，TCP可连 {} 个，严格通过 {} 个，失败 {} 个",
                            self.results.len(),
                            self.tcp_alive_count(),
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

        if should_clear_rx {
            self.rx = None;
        }
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

    fn summary_ui(&self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            summary_tile(ui, "总节点", self.results.len().to_string());
            summary_tile(
                ui,
                "TCP可连",
                format!(
                    "{} ({:.1}%)",
                    self.tcp_alive_count(),
                    self.percent(self.tcp_alive_count())
                ),
            );
            summary_tile(
                ui,
                "严格通过",
                format!(
                    "{} ({:.1}%)",
                    self.pass_count(),
                    self.percent(self.pass_count())
                ),
            );
            summary_tile(ui, "部分通过", self.warn_count().to_string());
            summary_tile(ui, "失败", self.fail_count().to_string());
        });

        ui.add_space(8.0);

        ui.horizontal_wrapped(|ui| {
            summary_tile(
                ui,
                "DNS通过",
                format!(
                    "{} ({:.1}%)",
                    self.dns_ok_count(),
                    self.percent(self.dns_ok_count())
                ),
            );
            summary_tile(
                ui,
                "TLS通过",
                format!(
                    "{} ({:.1}%)",
                    self.tls_passed_count(),
                    self.percent(self.tls_passed_count())
                ),
            );
            summary_tile(
                ui,
                "重复端点",
                self.start_summary.duplicate_endpoints.to_string(),
            );
            summary_tile(
                ui,
                "重名节点",
                self.start_summary.duplicate_names.to_string(),
            );
            summary_tile(
                ui,
                "TLS目标",
                self.start_summary.tls_target_count.to_string(),
            );
        });

        ui.add_space(8.0);

        ui.horizontal_wrapped(|ui| {
            summary_tile(
                ui,
                "高安全",
                format!(
                    "{} ({:.1}%)",
                    self.high_security_count(),
                    self.percent(self.high_security_count())
                ),
            );
            summary_tile(
                ui,
                "中安全",
                format!(
                    "{} ({:.1}%)",
                    self.medium_security_count(),
                    self.percent(self.medium_security_count())
                ),
            );
            summary_tile(
                ui,
                "低安全",
                format!(
                    "{} ({:.1}%)",
                    self.low_security_count(),
                    self.percent(self.low_security_count())
                ),
            );
            summary_tile(
                ui,
                "强加密",
                format!(
                    "{} ({:.1}%)",
                    self.strong_encryption_count(),
                    self.percent(self.strong_encryption_count())
                ),
            );
            summary_tile(
                ui,
                "中加密",
                format!(
                    "{} ({:.1}%)",
                    self.moderate_encryption_count(),
                    self.percent(self.moderate_encryption_count())
                ),
            );
            summary_tile(
                ui,
                "弱/明文",
                format!(
                    "{} ({:.1}%)",
                    self.weak_or_plaintext_count(),
                    self.percent(self.weak_or_plaintext_count())
                ),
            );
        });
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
        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::initial(280.0).at_least(180.0))
            .column(Column::initial(80.0).at_least(64.0))
            .column(Column::initial(240.0).at_least(140.0))
            .column(Column::initial(80.0).at_least(60.0))
            .column(Column::initial(90.0).at_least(70.0))
            .column(Column::initial(90.0).at_least(70.0))
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
                        response.on_hover_text(if result.security.note.is_empty() {
                            format!("安全等级: {}", result.security.security_level.label())
                        } else {
                            format!(
                                "安全等级: {}\n{}",
                                result.security.security_level.label(),
                                result.security.note
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
                        response.on_hover_text(format!(
                            "加密等级: {}",
                            result.security.encryption_level.label()
                        ));
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
                        let response = ui.label(RichText::new(short_text(&full, 86)).color(color));
                        response.on_hover_text(full);
                    });

                    if row.response().double_clicked() {
                        self.selected_result_index = Some(result_index);
                        self.show_node_detail = true;
                    }
                });
            });
    }
}

impl eframe::App for ClashCheckerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_events();

        if self.checking {
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
            ui.heading("Clash 订阅节点多项检测");
            ui.add_space(8.0);

            ui.horizontal(|ui| {
                ui.label("订阅 URL");
                ui.add(
                    egui::TextEdit::singleline(&mut self.subscription_url)
                        .desired_width(f32::INFINITY)
                        .hint_text("https://example.com/clash.yaml"),
                );
            });

            ui.add_space(8.0);

            ui.horizontal_wrapped(|ui| {
                ui.label("超时");
                ui.add(
                    egui::Slider::new(&mut self.timeout_secs, 1.0..=20.0)
                        .suffix(" 秒")
                        .step_by(1.0),
                );

                ui.label("采样次数");
                ui.add(egui::Slider::new(&mut self.attempts, 1..=10).suffix(" 次"));

                ui.label("并发");
                ui.add(egui::Slider::new(&mut self.workers, 1..=128).suffix(" 线程"));

                ui.checkbox(&mut self.enable_tls_probe, "TLS 握手检测");

                let button = egui::Button::new(if self.checking {
                    "检测中..."
                } else {
                    "开始检测"
                });

                if ui.add_enabled(!self.checking, button).clicked() {
                    self.start();
                }
            });

            ui.add_space(8.0);
            ui.label(&self.status_line);
            ui.add_space(6.0);
            ui.horizontal_wrapped(|ui| {
                ui.label("结果筛选");
                ui.selectable_value(&mut self.row_filter, RowFilter::All, "全部");
                ui.selectable_value(&mut self.row_filter, RowFilter::Pass, "通过");
                ui.selectable_value(&mut self.row_filter, RowFilter::Warn, "部分");
                ui.selectable_value(&mut self.row_filter, RowFilter::Fail, "失败");
                ui.selectable_value(&mut self.row_filter, RowFilter::HighRisk, "高风险");
                ui.label("搜索");
                ui.add(
                    egui::TextEdit::singleline(&mut self.search_text)
                        .desired_width(260.0)
                        .hint_text("节点名/服务器/原因"),
                );
            });
            ui.add_space(12.0);

            self.summary_ui(ui);
            ui.add_space(12.0);

            let filtered_indices = self.filtered_result_indices();
            ui.label(format!(
                "当前显示：{} / {}",
                filtered_indices.len(),
                self.results.len()
            ));
            ui.add_space(6.0);

            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.set_min_height(360.0);
                if self.results.is_empty() {
                    ui.centered_and_justified(|ui| {
                        ui.label("暂无检测结果");
                    });
                } else if filtered_indices.is_empty() {
                    ui.centered_and_justified(|ui| {
                        ui.label("筛选后没有匹配结果");
                    });
                } else {
                    egui::ScrollArea::horizontal()
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            ui.set_min_width(2400.0);
                            self.table_ui(ui, &filtered_indices);
                        });
                }
            });
        });

        if self.show_metric_guide {
            egui::Window::new("指标说明")
                .open(&mut self.show_metric_guide)
                .resizable(true)
                .default_width(760.0)
                .show(ctx, |ui| {
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
                    ui.label("TLS：对 TLS 类协议执行 ClientHello 预检的结果。");
                    ui.label("安全：综合协议、TLS、证书校验、稳定性得出的安全等级。");
                    ui.label("加密：根据协议和可见配置推断的加密强度。");
                    ui.label("评分：0~100 的综合安全分，越高越好。");
                    ui.label("状态：将 DNS/TCP/TLS 汇总后的最终判定与简要原因。");
                    ui.add_space(8.0);

                    ui.heading("筛选与搜索");
                    ui.label("结果筛选：按通过/部分/失败/高风险快速过滤。");
                    ui.label("搜索框：支持节点名、服务器、失败原因关键字匹配。");
                    ui.add_space(8.0);

                    ui.heading("详情查看");
                    ui.label("双击列表任意节点，可打开“节点详细信息”窗口。");
                    ui.label("详细信息里会显示协议参数、TLS状态、安全等级、评分与评估说明。");
                    ui.add_space(8.0);

                    ui.heading("常见疑问");
                    ui.label("“TLS 失败 (failed to fill whole buffer)” 通常不代表订阅链接有问题。");
                    ui.label("这更常见于节点服务端策略或预检方式兼容性导致的握手未返回完整响应。");
                    ui.label("如果 TCP 持续 3/3 成功，这个节点在真实客户端里仍可能可用。");
                    ui.add_space(8.0);

                    ui.heading("状态颜色");
                    ui.label("绿色：通过（指标整体健康）。");
                    ui.label("橙色：部分通过（有风险项，建议复测）。");
                    ui.label("红色：失败（当前检测项不通过）。");
                });
        }

        if self.show_node_detail {
            let selected = self
                .selected_result_index
                .and_then(|index| self.results.get(index).cloned());
            egui::Window::new("节点详细信息")
                .open(&mut self.show_node_detail)
                .resizable(true)
                .default_width(860.0)
                .show(ctx, |ui| {
                    let Some(result) = selected else {
                        ui.label("当前没有可查看的节点详情。");
                        return;
                    };

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
                                &format!("{}/{}", result.tcp_successes, result.tcp_attempts),
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
                                "TLS结果",
                                &match &result.tls_status {
                                    TlsProbeStatus::Passed => result
                                        .tls_latency_ms
                                        .map(|latency| format!("通过 ({latency} ms)"))
                                        .unwrap_or_else(|| "通过".to_owned()),
                                    TlsProbeStatus::Disabled => "关闭".to_owned(),
                                    TlsProbeStatus::Skipped(reason) => format!("跳过 ({reason})"),
                                    TlsProbeStatus::Failed(reason) => format!("失败 ({reason})"),
                                },
                            );
                            detail_row(ui, "安全等级", result.security.security_level.label());
                            detail_row(ui, "加密等级", result.security.encryption_level.label());
                            detail_row(ui, "安全评分", &format!("{} / 100", result.security.score));
                            detail_row(ui, "TLS配置", &option_bool_text(result.node.tls));
                            detail_row(
                                ui,
                                "跳过证书校验",
                                &option_bool_text(result.node.skip_cert_verify),
                            );
                            detail_row(ui, "Cipher", &option_text(result.node.cipher.as_deref()));
                            detail_row(ui, "Network", &option_text(result.node.network.as_deref()));
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
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RowFilter {
    All,
    Pass,
    Warn,
    Fail,
    HighRisk,
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

fn summary_tile(ui: &mut egui::Ui, label: &str, value: String) {
    egui::Frame::group(ui.style())
        .inner_margin(egui::Margin::same(12.0))
        .show(ui, |ui| {
            ui.set_min_width(120.0);
            ui.label(label);
            ui.heading(value);
        });
}

fn detail_row(ui: &mut egui::Ui, key: &str, value: &str) {
    ui.strong(key);
    ui.label(value);
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
