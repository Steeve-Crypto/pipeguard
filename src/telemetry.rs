use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Initialize tracing subscriber.
///
/// - Default: human-readable pretty logs
/// - Set `RUST_LOG=pipeguard=debug` (or `info`, `trace`) to control verbosity
/// - Set `PIPEGUARD_LOG_FORMAT=json` for structured JSON logs (good for collectors)
pub fn init() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("pipeguard=info,warn"));

    let json = std::env::var("PIPEGUARD_LOG_FORMAT")
        .map(|v| v.eq_ignore_ascii_case("json"))
        .unwrap_or(false);

    if json {
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().json().with_target(true).with_thread_ids(false))
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(
                fmt::layer()
                    .with_target(false)
                    .with_thread_ids(false)
                    .compact(),
            )
            .init();
    }
}
