mod app;
mod checker;
mod subscription;
mod update;

fn main() -> eframe::Result<()> {
    let window_title = format!("Clash Node Checker v{}", env!("CARGO_PKG_VERSION"));
    let mut options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([980.0, 680.0])
            .with_min_inner_size([760.0, 520.0])
            .with_title(&window_title),
        ..Default::default()
    };

    #[cfg(target_os = "windows")]
    {
        options.renderer = eframe::Renderer::Glow;
    }

    eframe::run_native(
        &window_title,
        options,
        Box::new(|cc| Ok(Box::new(app::ClashCheckerApp::new(cc)))),
    )
}
