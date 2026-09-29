#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable
    )
)]
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(version, about = "Native local-first job rejection review workspace")]
struct Args {
    #[arg(long)]
    data_dir: Option<PathBuf>,
    /// Synthetic offline demo. No account, model or email sending.
    #[arg(long)]
    demo: bool,
    /// Capture synthetic UI to PNG and exit; never allowed for a real mailbox.
    #[arg(long, requires = "demo")]
    screenshot: Option<PathBuf>,
    #[arg(long, requires = "demo", value_parser = ["overview", "review", "activity", "local-ai", "settings"])]
    demo_view: Option<String>,
    #[arg(long, requires = "demo", value_parser = clap::value_parser!(u32).range(1180..=3840))]
    demo_width: Option<u32>,
    #[arg(long, requires = "demo", value_parser = clap::value_parser!(u32).range(760..=2160))]
    demo_height: Option<u32>,
}
fn main() -> eframe::Result<()> {
    let args = Args::parse();
    // Fail closed instead of silently writing private state into the current directory.
    let dir = match args.data_dir {
        Some(path) => path,
        None => rejection_rejector::config::data_dir()
            .map_err(|e| eframe::Error::AppCreation(e.into()))?,
    };
    let options = eframe::NativeOptions {
        renderer: eframe::Renderer::Glow,
        viewport: eframe::egui::ViewportBuilder::default()
            .with_visible(true)
            .with_inner_size([
                args.demo_width.unwrap_or(1440) as f32,
                args.demo_height.unwrap_or(940) as f32,
            ])
            .with_min_inner_size([1180.0, 760.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Rejection Rejector",
        options,
        Box::new(move |cc| {
            let mut app = rejection_rejector::gui::App::new(cc, dir, args.demo, args.screenshot);
            if let Some(view) = &args.demo_view {
                app.set_demo_view(view);
            }
            Ok(Box::new(app))
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn screenshots_and_demo_controls_require_demo() {
        assert!(Args::try_parse_from(["rr", "--screenshot", "private.png"]).is_err());
        assert!(Args::try_parse_from(["rr", "--demo-view", "settings"]).is_err());
        assert!(Args::try_parse_from(["rr", "--demo", "--screenshot", "synthetic.png"]).is_ok());
    }
    #[test]
    fn ordinary_start_and_bounded_demo_window_are_valid() {
        assert!(Args::try_parse_from(["rr"]).is_ok());
        assert!(
            Args::try_parse_from([
                "rr",
                "--demo",
                "--demo-width",
                "1180",
                "--demo-height",
                "760"
            ])
            .is_ok()
        );
        assert!(Args::try_parse_from(["rr", "--demo", "--demo-width", "10"]).is_err());
    }
}
