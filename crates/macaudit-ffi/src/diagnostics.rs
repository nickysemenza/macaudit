use std::sync::OnceLock;

pub fn initialize() {
    let Ok(value) = std::env::var("RUST_LOG") else {
        return;
    };
    let Some(filter) = filter(&value) else {
        return;
    };
    static INITIALIZED: OnceLock<()> = OnceLock::new();
    INITIALIZED.get_or_init(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .with_ansi(false)
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
            .try_init();
    });
}

fn filter(value: &str) -> Option<tracing_subscriber::EnvFilter> {
    if value.trim().is_empty() {
        return None;
    }
    tracing_subscriber::EnvFilter::try_new(value).ok()
}

pub fn query(
    operation: &'static str,
    run_id: u64,
    request_id: u64,
    revision: u64,
) -> tracing::Span {
    tracing::debug_span!(
        "ffi_query",
        operation,
        run_id,
        request_id,
        revision,
        rows = tracing::field::Empty,
        bytes = tracing::field::Empty,
    )
}

pub fn serialization(operation: &'static str) -> tracing::Span {
    tracing::debug_span!("ffi_serialize", operation, bytes = tracing::field::Empty)
}

pub fn query_rows<T: serde::Serialize>(timing: &tracing::Span, rows: &[T]) {
    timing.record("rows", rows.len());
    if timing.is_disabled() {
        return;
    }
    let serialization = serialization("query_rows_json_size");
    let _serialization = serialization.enter();
    if let Ok(bytes) = macaudit::inventory::serialized_size(rows) {
        timing.record("bytes", bytes);
        serialization.record("bytes", bytes);
    }
}

pub fn publication(run_id: u64, revision: u64) -> tracing::Span {
    tracing::debug_span!(
        "ffi_publication",
        run_id,
        request_id = 0_u64,
        revision,
        rows = tracing::field::Empty,
        bytes = tracing::field::Empty,
        reserved_bytes = tracing::field::Empty,
    )
}

#[cfg(test)]
mod tests {
    use super::filter;

    #[test]
    fn logging_requires_an_explicit_nonempty_valid_filter() {
        assert!(filter("").is_none());
        assert!(filter("   ").is_none());
        assert!(filter("[invalid").is_none());
        assert!(filter("macaudit_ffi=debug").is_some());
        assert!(filter("off").is_some());
    }
}
