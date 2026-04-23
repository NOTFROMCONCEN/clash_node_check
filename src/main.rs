mod app;
mod checker;
mod subscription;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([980.0, 680.0])
            .with_min_inner_size([760.0, 520.0])
            .with_title("Clash Node Checker"),
        ..Default::default()
    };

    eframe::run_native(
        "Clash Node Checker",
        options,
        Box::new(|cc| Ok(Box::new(app::ClashCheckerApp::new(cc)))),
    )
}
