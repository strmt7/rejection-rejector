#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use clap::Parser;
use std::path::PathBuf;
#[derive(Parser)]
#[command(version, about = "Native local-first job rejection review workspace")]
struct Args {
    #[arg(long)]
    data_dir: Option<PathBuf>,
    /// Synthetic offline demo; no account, credentials, model or email sending.
    #[arg(long)]
    demo: bool,
    /// Capture the native demo UI to PNG and exit. Requires --demo.
    #[arg(long, requires = "demo")]
    screenshot: Option<PathBuf>,
}
fn main() -> eframe::Result<()> {
    let args = Args::parse();
    let dir = args.data_dir.unwrap_or_else(|| {
        rejection_rejector::config::data_dir()
            .unwrap_or_else(|_| PathBuf::from("rejection-rejector-data"))
    });
    let options = eframe::NativeOptions {
        renderer: eframe::Renderer::Glow,
        viewport: eframe::egui::ViewportBuilder::default()
            .with_visible(true)
            .with_inner_size([1440.0, 940.0])
            .with_min_inner_size([1180.0, 760.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Rejection Rejector",
        options,
        Box::new(move |cc| {
            Ok(Box::new(rejection_rejector::gui::App::new(
                cc,
                dir,
                args.demo,
                args.screenshot,
            )))
        }),
    )
}
