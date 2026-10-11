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
    #[arg(long, conflicts_with = "recovery")]
    demo: bool,
    /// Pre-open disaster-recovery UI. The normal worker/vault is never started.
    #[arg(long, conflicts_with = "demo")]
    recovery: bool,
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
    launch(Args::parse())
}

/// Build the native window options for the requested presentation.
///
/// Inputs: `args` — parsed CLI arguments. Output: [`eframe::NativeOptions`]
/// with the Glow renderer, the requested (or default 1440×940) inner size
/// and the minimum usable window size.
fn native_options(args: &Args) -> eframe::NativeOptions {
    eframe::NativeOptions {
        renderer: eframe::Renderer::Glow,
        viewport: eframe::egui::ViewportBuilder::default()
            .with_visible(true)
            .with_inner_size([
                args.demo_width.unwrap_or(1440) as f32,
                args.demo_height.unwrap_or(940) as f32,
            ])
            .with_min_inner_size([1180.0, 760.0]),
        ..Default::default()
    }
}

/// Create the application the arguments ask for.
///
/// Inputs: `cc` — egui creation context; `args` — parsed CLI arguments;
/// `dir` — resolved data directory. Output: the disaster-recovery app for
/// `--recovery`, otherwise the workspace app (demo and screenshot flags
/// forwarded, `--demo-view` applied after construction).
fn create_app(
    cc: &eframe::CreationContext<'_>,
    args: Args,
    dir: PathBuf,
) -> Result<Box<dyn eframe::App>, Box<dyn std::error::Error + Send + Sync>> {
    if args.recovery {
        return Ok(
            Box::new(rejection_rejector::gui::RecoveryApp::new(cc, dir)) as Box<dyn eframe::App>
        );
    }
    let mut app = rejection_rejector::gui::App::new(cc, dir, args.demo, args.screenshot);
    if let Some(view) = &args.demo_view {
        app.set_demo_view(view);
    }
    Ok(Box::new(app) as Box<dyn eframe::App>)
}

/// Launch the native window for the requested application.
///
/// Inputs: `args` — parsed CLI arguments. Output: the eframe run result;
/// without `--data-dir` the platform data directory is resolved first and a
/// resolution failure is reported instead of writing into the current
/// directory.
fn launch(args: Args) -> eframe::Result<()> {
    // Fail closed instead of silently writing private state into the current directory.
    let dir = match &args.data_dir {
        Some(path) => path.clone(),
        None => rejection_rejector::config::data_dir()
            .map_err(|e| eframe::Error::AppCreation(e.into()))?,
    };
    eframe::run_native(
        "Rejection Rejector",
        native_options(&args),
        Box::new(move |cc| create_app(cc, args, dir)),
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
        assert!(Args::try_parse_from(["rr", "--recovery"]).is_ok());
        assert!(Args::try_parse_from(["rr", "--recovery", "--demo"]).is_err());
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

    /// Window sizing falls back to the documented default exactly.
    ///
    /// Why: the layout is tuned for 1440×940 — a silent fallback change
    /// would break the screenshot baselines.
    #[test]
    fn native_options_use_the_documented_window_sizes() {
        let args = Args::try_parse_from(["rr"]).unwrap();
        let options = native_options(&args);
        assert_eq!(
            options.viewport.inner_size,
            Some(eframe::egui::vec2(1440.0, 940.0)),
            "default inner size"
        );
        assert_eq!(
            options.viewport.min_inner_size,
            Some(eframe::egui::vec2(1180.0, 760.0))
        );

        let args = Args::try_parse_from([
            "rr",
            "--demo",
            "--demo-width",
            "1200",
            "--demo-height",
            "800",
        ])
        .unwrap();
        let options = native_options(&args);
        assert_eq!(
            options.viewport.inner_size,
            Some(eframe::egui::vec2(1200.0, 800.0)),
            "explicit inner size wins"
        );
    }

    /// The app creator builds exactly the application the flags request.
    ///
    /// Why: `--recovery` must never start the normal worker/vault, and
    /// `--demo-view` must land on the requested screen.
    #[test]
    fn create_app_honours_recovery_demo_and_view_flags() {
        let ctx = eframe::egui::Context::default();
        let cc = eframe::CreationContext::_new_kittest(ctx.clone());
        let dir = tempfile::tempdir().unwrap();

        let args = Args::try_parse_from(["rr", "--recovery"]).unwrap();
        let app = create_app(&cc, args, dir.path().to_path_buf()).unwrap();
        assert!(
            rendered_labels(&ctx, app)
                .iter()
                .any(|l| l == "Disaster Recovery Mode"),
            "--recovery builds the disaster-recovery app"
        );

        let args = Args::try_parse_from(["rr", "--demo", "--demo-view", "settings"]).unwrap();
        let app = create_app(&cc, args, dir.path().to_path_buf()).unwrap();
        let labels = rendered_labels(&ctx, app);
        assert!(
            labels.iter().any(|l| l == "Settings"),
            "the demo view lands on the requested screen: {labels:?}"
        );

        let args = Args::try_parse_from(["rr"]).unwrap();
        let app = create_app(&cc, args, dir.path().to_path_buf()).unwrap();
        let labels = rendered_labels(&ctx, app);
        assert!(
            labels.iter().any(|l| l == "Pause worker")
                && !labels.iter().any(|l| l == "Disaster Recovery Mode"),
            "the normal flags build the workspace app: {labels:?}"
        );
    }

    /// Render one headless frame of the created app and collect its widget
    /// labels.
    ///
    /// Inputs: `ctx` — egui context; `app` — created application. Output:
    /// the AccessKit label/value texts of the first frame's widget tree.
    fn rendered_labels(ctx: &eframe::egui::Context, mut app: Box<dyn eframe::App>) -> Vec<String> {
        ctx.enable_accesskit();
        // A fresh context emits no widget tree on its first pass; warm it up.
        let mut warm = ctx.run_ui(eframe::egui::RawInput::default(), |root_ui| {
            let mut frame = eframe::Frame::_new_kittest();
            app.ui(root_ui, &mut frame);
        });
        warm.textures_delta.clear();
        let mut out = ctx.run_ui(eframe::egui::RawInput::default(), |root_ui| {
            let mut frame = eframe::Frame::_new_kittest();
            app.ui(root_ui, &mut frame);
        });
        out.textures_delta.clear();
        let update = out
            .platform_output
            .accesskit_update
            .expect("accesskit tree");
        update
            .nodes
            .iter()
            .filter_map(|(_, node)| node.label().or_else(|| node.value()).map(str::to_owned))
            .collect()
    }
}
