//! Swift-only binding generator. Kept as a workspace crate so the bindgen
//! version is locked to the `uniffi` runtime compiled into `macaudit-ffi` —
//! the generated Swift carries per-symbol checksums that must match the
//! static library it loads.

fn main() {
    uniffi::uniffi_bindgen_swift()
}
