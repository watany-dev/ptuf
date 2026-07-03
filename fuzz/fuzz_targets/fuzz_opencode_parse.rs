#![no_main]

//! Coverage-guided fuzzing of the OpenCode hook payload normaliser.
//!
//! Drives arbitrary bytes through [`ptuf::cli::fuzz_opencode_parse`] so the
//! OpenCode adapter's JSON extraction and tool-name mapping never panic.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let body = String::from_utf8_lossy(data);
    ptuf::cli::fuzz_opencode_parse(&body);
});
