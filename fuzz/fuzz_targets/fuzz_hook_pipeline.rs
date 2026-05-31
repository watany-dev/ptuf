#![no_main]

//! Coverage-guided fuzzing of the hook decision pipeline.
//!
//! Drives arbitrary bytes through `HookInput` deserialization and, on a
//! successful parse, the full `Engine::decide` evaluation (fact
//! extraction + every built-in rule + decision aggregation). This is the
//! coverage-guided counterpart of the `pbt_run_hook_fails_closed_for_
//! arbitrary_stdin` property test.
//!
//! The engine is built once via `Engine::builder()` — never
//! `Engine::for_cwd()` — so the run is deterministic and free of
//! filesystem I/O.

use libfuzzer_sys::fuzz_target;
use ptuf::config::{self, Config};
use ptuf::{Engine, HookInput};
use std::path::Path;

fuzz_target!(|data: &[u8]| {
    let source = String::from_utf8_lossy(data);
    let mut config = config::yaml::parse_str(Path::new("fuzz-policy.yaml"), &source)
        .ok()
        .map(|raw| config::merge::merge(vec![raw]))
        .unwrap_or_default();
    config.plugin_paths.clear();
    if let Ok(engine) = Engine::with_config(config) {
        if let Ok(input) = serde_json::from_slice::<HookInput>(data) {
            let _ = engine.decide(&input);
        }
    }
});
