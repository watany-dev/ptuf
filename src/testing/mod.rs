//! Test-only utilities and cross-module property tests.
//!
//! The whole module is `#[cfg(test)]`, so it disappears entirely from
//! `cargo build`-produced binaries and from the crate's public API.
//! [`proptest`] exposes the strategy implementations that per-module
//! `#[cfg(test)] mod tests` blocks share; the `*_pbt` modules host the
//! cross-module properties that have no single owning module.

pub(crate) mod proptest;

mod cli_parse_pbt;
mod engine_pbt;
mod filter_pbt;
mod rules_pbt;
