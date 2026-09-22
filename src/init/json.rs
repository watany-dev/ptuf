//! JSON document helpers shared by the init adapters.
//!
//! Every hook-config adapter (`claude_code`, `codex`, `copilot`,
//! `cursor`, `kiro`) reads a JSON settings file that may be absent or
//! blank, walks down to a `hooks.<event>` array creating the missing
//! levels, and appends its own entry shape. Only the entry shape
//! actually differs between adapters, so everything above it lives here.

use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use serde_json::{Map, Value, json};

use super::InitError;

/// Read `path` as a JSON document. A missing file and a blank file both
/// yield `default()` — installing into a host that has never written
/// its config is the common case, not an error.
pub(crate) fn read_or_default<F>(path: &Path, default: F) -> Result<Value, InitError>
where
    F: FnOnce() -> Value,
{
    match fs::read_to_string(path) {
        Ok(s) if s.trim().is_empty() => Ok(default()),
        Ok(s) => serde_json::from_str(&s).map_err(|e| InitError::Json {
            path: path.to_path_buf(),
            message: e.to_string(),
        }),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(default()),
        Err(e) => Err(InitError::Io {
            path: path.to_path_buf(),
            source: e,
        }),
    }
}

/// [`read_or_default`] with an empty JSON object as the default.
pub(crate) fn read_object(path: &Path) -> Result<Value, InitError> {
    read_or_default(path, || json!({}))
}

/// `map[key]` as a mutable object, inserting `{}` when absent. `None`
/// when the key is present but holds a non-object.
pub(crate) fn ensure_object<'a>(
    map: &'a mut Map<String, Value>,
    key: &str,
) -> Option<&'a mut Map<String, Value>> {
    map.entry(key.to_string())
        .or_insert_with(|| json!({}))
        .as_object_mut()
}

/// `map[key]` as a mutable array, inserting `[]` when absent. `None`
/// when the key is present but holds a non-array.
pub(crate) fn ensure_array<'a>(
    map: &'a mut Map<String, Value>,
    key: &str,
) -> Option<&'a mut Vec<Value>> {
    map.entry(key.to_string())
        .or_insert_with(|| json!([]))
        .as_array_mut()
}

/// Pin the document's `version` to `1`, inserting it when absent. Any
/// other value is a schema the installer does not know how to patch.
pub(crate) fn ensure_version(root: &mut Value, path: &Path) -> Result<(), InitError> {
    let Some(map) = root.as_object_mut() else {
        return Err(schema(path, "top-level value must be a JSON object"));
    };
    match map.get("version") {
        None => {
            map.insert("version".to_string(), json!(1));
            Ok(())
        },
        Some(v) if v == &json!(1) => Ok(()),
        Some(other) => Err(schema(
            path,
            &format!("`version` must be 1 (found {other})"),
        )),
    }
}

/// `root.hooks.<event>` as a mutable array, creating both levels when
/// absent. This is the shared prologue of every adapter's
/// `append_hook`; the adapter only supplies the entry it pushes.
pub(crate) fn hook_array<'a>(
    root: &'a mut Value,
    path: &Path,
    event: &str,
) -> Result<&'a mut Vec<Value>, InitError> {
    let map = root
        .as_object_mut()
        .ok_or_else(|| schema(path, "top-level value must be a JSON object"))?;
    let hooks =
        ensure_object(map, "hooks").ok_or_else(|| schema(path, "`hooks` must be an object"))?;
    ensure_array(hooks, event)
        .ok_or_else(|| schema(path, &format!("`hooks.{event}` must be an array")))
}

fn schema(path: &Path, message: &str) -> InitError {
    InitError::Schema {
        path: path.to_path_buf(),
        message: message.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("ptuf-init-json-{name}-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    #[test]
    fn read_object_treats_missing_and_blank_as_empty_object() {
        let dir = tmpdir("read-default");
        let missing = dir.join("absent.json");
        assert_eq!(read_object(&missing).expect("missing"), json!({}));

        let blank = dir.join("blank.json");
        fs::write(&blank, "  \n").expect("write");
        assert_eq!(read_object(&blank).expect("blank"), json!({}));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_or_default_uses_the_callers_skeleton() {
        let dir = tmpdir("read-skeleton");
        let missing = dir.join("absent.json");
        let got = read_or_default(&missing, || json!({"name": "agent"})).expect("missing");
        assert_eq!(got, json!({"name": "agent"}));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_object_surfaces_malformed_json_and_io_errors() {
        let dir = tmpdir("read-errors");
        let bad = dir.join("bad.json");
        fs::write(&bad, "{").expect("write");
        assert!(
            matches!(read_object(&bad), Err(InitError::Json { .. })),
            "malformed JSON must surface as InitError::Json",
        );

        let as_dir = dir.join("nested");
        fs::create_dir_all(&as_dir).expect("mkdir");
        assert!(
            matches!(read_object(&as_dir), Err(InitError::Io { .. })),
            "reading a directory must surface as InitError::Io",
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn ensure_helpers_create_missing_levels_and_reject_wrong_types() {
        let mut map = Map::new();
        ensure_object(&mut map, "hooks").expect("created object");
        ensure_array(&mut map, "list").expect("created array");
        assert_eq!(map["hooks"], json!({}));
        assert_eq!(map["list"], json!([]));

        map.insert("scalar".to_string(), json!(1));
        assert!(ensure_object(&mut map, "scalar").is_none());
        assert!(ensure_array(&mut map, "scalar").is_none());
    }

    #[test]
    fn ensure_version_inserts_accepts_and_rejects() {
        let path = Path::new("hooks.json");

        let mut fresh = json!({});
        ensure_version(&mut fresh, path).expect("insert");
        assert_eq!(fresh["version"], json!(1));

        let mut already = json!({"version": 1});
        ensure_version(&mut already, path).expect("accept");

        let mut wrong = json!({"version": 2});
        let err = ensure_version(&mut wrong, path).expect_err("reject");
        assert!(matches!(err, InitError::Schema { .. }), "got {err:?}");

        let mut not_object = json!([]);
        let err = ensure_version(&mut not_object, path).expect_err("reject non-object");
        assert!(matches!(err, InitError::Schema { .. }), "got {err:?}");
    }

    #[test]
    fn hook_array_creates_both_levels() {
        let path = Path::new("hooks.json");
        let mut root = json!({});
        hook_array(&mut root, path, "preToolUse")
            .expect("array")
            .push(json!({"command": "ptuf"}));
        assert_eq!(
            root,
            json!({"hooks": {"preToolUse": [{"command": "ptuf"}]}})
        );
    }

    #[test]
    fn hook_array_rejects_every_wrong_shape() {
        let path = Path::new("hooks.json");
        for mut root in [
            json!([]),
            json!({"hooks": 1}),
            json!({"hooks": {"preToolUse": 1}}),
        ] {
            let err = hook_array(&mut root, path, "preToolUse").expect_err("must reject");
            assert!(matches!(err, InitError::Schema { .. }), "got {err:?}");
        }
    }
}
