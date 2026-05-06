//! Test-only utilities (property-based testing strategies).
//!
//! Gated behind `#[cfg(test)]` so the module disappears entirely from
//! `cargo build`-produced binaries. Each submodule exposes
//! `proptest` strategy implementations that the
//! per-module `#[cfg(test)] mod tests` blocks share, plus the
//! integration test in `tests/engine_proptest.rs`.

pub mod proptest;
