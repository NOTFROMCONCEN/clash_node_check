use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use eframe::egui;
use egui_extras::{Column, TableBuilder};

use crate::checker::{start_check, CheckEvent, CheckOptions, NodeCheckResult, NodeStatus};

pub struct ClashCheckerApp {
    subscription_url: String,
    timeout_secs: f32,
    checking: bool,
    status_line: String,
    results: Vec<NodeCheckResult>,
    rx: Option<Receiver<CheckEvent>>,
}

impl ClashCheckerApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        Self {
            subscription_url: String::new(),
            timeout_secs: 4.0,
            checking: false,
            status_line: "输入 Clash 订阅地址后开始检测".to_owned(),
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
        };

        self.results.clear();
        self.rx = Some(rx);
        self.checking = true;
        self.status_line = "正在下载订阅并检测节点...".to_owned();

        start_check(url, options, tx);
    }

    fn drain_events(&mut self) {
        let mut should_clear_rx = false;

        if let Some(rx) = &self.rx {
            while let Ok(event) = rx.try_recv() {
                match event {
                    CheckEvent::Started { total } => {
                        self.results.reserve(total);
                        self.status_line = format!("解析到 {total} 个节点，正在检测...");
                    }
                    CheckEvent::NodeFinished(result) => {
                        self.results.push(result);
                        let checked = self.results.len();
                        let alive = self.alive_count();
                        self.status_line = format!(
                            "已检测 {checked} 个节点，存活 {alive} 个，存活率 {:.1}%",
                            self.alive_percent()
                        );
                    }
                    CheckEvent::Finished => {
                        self.checking = false;
                        self.status_line = format!(
                            "检测完成：共 {} 个，存活 {} 个，存活率 {:.1}%",
                            self.results.len(),
                            self.alive_count(),
                            self.alive_percent()
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

    fn alive_count(&self) -> usize {
        self.results
            .iter()
            .filter(|result| result.status == NodeStatus::Alive)
            .count()
    }

    fn alive_percent(&self) -> f32 {
        if self.results.is_empty() {
            0.0
        } else {
            self.alive_count() as f32 / self.results.len() as f32 * 100.0
        }
    }

    fn summary_ui(&self, ui: &mut egui::Ui) {
        let total = self.results.len();
        let alive = self.alive_count();
        let dead = total.saturating_sub(alive);

        ui.horizontal(|ui| {
            summary_tile(ui, "总节点", total.to_string());
            summary_tile(ui, "存活", alive.to_string());
            summary_tile(ui, "失败", dead.to_string());
            summary_tile(ui, "存活率", format!("{:.1}%", self.alive_percent()));
        });
    }

    fn table_ui(&self, ui: &mut egui::Ui) {
        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::initial(220.0).at_least(120.0))
            .column(Column::initial(80.0).at_least(64.0))
            .column(Column::initial(180.0).at_least(120.0))
            .column(Column::initial(80.0).at_least(60.0))
            .column(Column::initial(80.0).at_least(60.0))
            .column(Column::remainder().at_least(160.0))
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
                    ui.strong("延迟");
                });
                header.col(|ui| {
                    ui.strong("状态");
                });
            })
            .body(|body| {
                body.rows(26.0, self.results.len(), |mut row| {
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
                                .latency_ms
                                .map(|value| format!("{value} ms"))
                                .unwrap_or_else(|| "-".to_owned()),
                        );
                    });
                    row.col(|ui| {
                        let color = match result.status {
                            NodeStatus::Pending => ui.visuals().weak_text_color(),
                            NodeStatus::Alive => egui::Color32::from_rgb(32, 145, 91),
                            NodeStatus::Dead => egui::Color32::from_rgb(190, 64, 64),
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
            ui.heading("Clash 订阅节点存活检测");
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
                    egui::Slider::new(&mut self.timeout_secs, 1.0..=15.0)
                        .suffix(" 秒")
                        .step_by(1.0),
                );

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

fn summary_tile(ui: &mut egui::Ui, label: &str, value: String) {
    egui::Frame::group(ui.style())
        .inner_margin(egui::Margin::same(12.0))
        .show(ui, |ui| {
            ui.set_min_width(120.0);
            ui.label(label);
            ui.heading(value);
        });
}
