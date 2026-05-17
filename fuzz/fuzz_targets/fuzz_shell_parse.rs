#![no_main]

//! Coverage-guided fuzzing of the Bash tokenizer / parser.
//!
//! `facts::shell::parse` is a trust boundary: it consumes a raw command
//! string lifted straight from a coding agent's tool call. This target
//! drives it with arbitrary byte sequences (decoded lossily, mirroring
//! the production path) to assert the parser is total — it must never
//! panic, never hang, and the tokenizer must always make forward
//! progress (`debug_assert!(advanced > 0)` in `facts::shell`).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let command = String::from_utf8_lossy(data);
    let _ = ptuf::facts::shell::parse(&command);
});
