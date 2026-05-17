#![no_main]

//! Coverage-guided fuzzing of the plugin loader + `when:` DSL compiler.
//!
//! A plugin YAML (`apiVersion: ptuf.dev/v1, kind: Plugin`) is untrusted
//! input: `plugin::load_str` parses the document, validates the
//! envelope, and compiles each rule's `when:` condition tree into the
//! DSL AST. This target drives arbitrary bytes through that whole path
//! to assert the loader and the condition-tree compiler never panic.

use libfuzzer_sys::fuzz_target;
use ptuf::plugin;
use std::path::Path;

fuzz_target!(|data: &[u8]| {
    let source = String::from_utf8_lossy(data);
    let _ = plugin::load_str(Path::new("fuzz-plugin.yaml"), &source);
});
