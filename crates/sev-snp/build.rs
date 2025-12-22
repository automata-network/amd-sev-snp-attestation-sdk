extern crate cbindgen;

use std::env;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let bindings_filename = format!("{}/c/sev_snp.h", &crate_dir);

    let clib_enabled = env::var_os("CARGO_FEATURE_CLIB").is_some();
    if clib_enabled {
        // Build the C bindings header.
        cbindgen::Builder::new()
            .with_crate(&crate_dir)
            .with_language(cbindgen::Language::C)
            .generate()
            .expect("Unable to generate C bindings")
            .write_to_file(&bindings_filename);
    }
}
