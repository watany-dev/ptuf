//! Shared helpers for agent-specific input adapters.

use serde_json::{Map, Value};

/// Remove the first key in `keys` whose value is a JSON string and
/// return the owned string. Used by the Copilot and Kiro adapters to
/// promote alias keys (e.g. `cmd`/`script` → `command`) into the
/// canonical input shape consumed by the engine.
pub(super) fn take_first_string(args: &mut Map<String, Value>, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(Value::String(s)) = args.remove(*key) {
            return Some(s);
        }
    }
    None
}
