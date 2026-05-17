#![no_main]

//! Coverage-guided fuzzing of the YAML config parser + layer merge.
//!
//! Each policy scope (`/etc/ptuf`, `~/.config/ptuf`, `.ptuf.yaml`,
//! `.ptuf.local.yaml`) is a trust boundary. This target drives arbitrary
//! bytes through `config::yaml::parse_str` (which also compiles any
//! embedded allowlist `when:` DSL) and, on success, folds the parsed
//! layer through `config::merge::merge` to exercise the merge logic.

use libfuzzer_sys::fuzz_target;
use ptuf::config;
use std::path::Path;

fuzz_target!(|data: &[u8]| {
    let source = String::from_utf8_lossy(data);
    if let Ok(raw) = config::yaml::parse_str(Path::new("fuzz.yaml"), &source) {
        let _ = config::merge::merge(vec![raw]);
    }
});
