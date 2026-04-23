use std::fs;
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use eframe::egui;
use egui_extras::{Column, TableBuilder};

use crate::checker::{
    start_check, CheckEvent, CheckOptions, NodeCheckResult, NodeStatus, StartSummary,
    TlsProbeStatus,
};

pub struct ClashCheckerApp {
    subscription_url: String,
    timeout_secs: f32,
    attempts: u32,
    workers: u32,
    enable_tls_probe: bool,
    checking: bool,
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
            checking: false,
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

    fn percent(&self, count: usize) -> f32 {
        if self.results.is_empty() {
            0.0
        } else {
            count as f32 / self.results.len() as f32 * 100.0
        }
    }

    fn summary_ui(&self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
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

        ui.horizontal(|ui| {
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
    }

    fn table_ui(&self, ui: &mut egui::Ui) {
        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::initial(220.0).at_least(140.0))
            .column(Column::initial(80.0).at_least(64.0))
            .column(Column::initial(180.0).at_least(120.0))
            .column(Column::initial(80.0).at_least(60.0))
            .column(Column::initial(90.0).at_least(70.0))
            .column(Column::initial(90.0).at_least(70.0))
            .column(Column::initial(120.0).at_least(90.0))
            .column(Column::remainder().at_least(220.0))
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
                    ui.strong("状态");
                });
            })
            .body(|body| {
                body.rows(28.0, self.results.len(), |mut row| {
                    let result = &self.results[row.index()];
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
                        ui.colored_label(tls_color, tls_text);
                    });
                    row.col(|ui| {
                        let color = match result.status {
                            NodeStatus::Pass => egui::Color32::from_rgb(32, 145, 91),
                            NodeStatus::Warn => egui::Color32::from_rgb(194, 122, 0),
                            NodeStatus::Fail => egui::Color32::from_rgb(190, 64, 64),
                        };
                        ui.colored_label(
                            color,
                            format!("{} - {}", result.status.label(), result.message),
                        );
                    });
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

            ui.horizontal(|ui| {
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
            ui.add_space(12.0);

            self.summary_ui(ui);
            ui.add_space(12.0);

            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.set_min_height(360.0);
                if self.results.is_empty() {
                    ui.centered_and_justified(|ui| {
                        ui.label("暂无检测结果");
                    });
                } else {
                    self.table_ui(ui);
                }
            });
        });
    }
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
