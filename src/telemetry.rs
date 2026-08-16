use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Initialize tracing subscriber.
///
/// Logs always go to **stderr** so stdout stays clean for `--json` / `--sarif`.
///
/// - Default filter: `pipeguard=info,warn`
/// - Override with `RUST_LOG` (e.g. `RUST_LOG=pipeguard=debug` or `RUST_LOG=off`)
/// - Set `PIPEGUARD_LOG_FORMAT=json` for structured JSON logs on stderr
pub fn init() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("pipeguard=info,warn"));

    let json = std::env::var("PIPEGUARD_LOG_FORMAT")
        .map(|v| v.eq_ignore_ascii_case("json"))
        .unwrap_or(false);

    if json {
        tracing_subscriber::registry()
            .with(filter)
            .with(
                fmt::layer()
                    .json()
                    .with_writer(std::io::stderr)
                    .with_target(true)
                    .with_thread_ids(false),
            )
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(
                fmt::layer()
                    .with_writer(std::io::stderr)
                    .with_target(false)
                    .with_thread_ids(false)
                    .compact(),
            )
            .init();
    }
}
