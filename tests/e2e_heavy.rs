//! Heavy E2E tests reproducing real-world ptuf invocation patterns.
//!
//! All tests are `#[ignore]` so `cargo test` and `make check` skip
//! them. Run via `make e2e` (or
//! `cargo test --features testing --test e2e_heavy -- --ignored --test-threads=1`).
//!
//! Six axes:
//! - `leak`            — fd / tempfile / child-process residue
//! - `giant_input`     — 8 MiB stdin, 1000-stage pipeline, oversized configs
//! - `concurrent`      — sequential 200 and parallel 10×100 invocations
//! - `full_config_stack` — 4-layer config + plugin + audit end-to-end
//! - `adapter_parity`  — all 5 agents in their native payload shapes
//! - `pathological_input` — malformed / oversized / deeply nested payloads
//!
//! The shared `common::spawn` helper kills and reaps the child once a
//! timeout elapses, so a hung ptuf surfaces as a test *failure* rather
//! than wedging `make e2e`; `common::assert_clean_exit` additionally
//! flags a signal kill (crash). Every axis below relies on this.

// Some inner-module helpers (e.g. `leak::ptuf_tempfile_names`) live
// outside `#[test]` bodies and so fall outside `clippy.toml`'s
// `allow-*-in-tests`. Relax explicitly.
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

const ALLOW_PAYLOAD: &[u8] = br#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#;
const DENY_PAYLOAD: &[u8] = br#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#;

// ---------------------------------------------------------------------
// Axis 1: resource leak detection (Linux only)
// ---------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod leak {
    use super::common::{SpawnConfig, open_fd_count, spawn};
    use std::collections::BTreeSet;

    const ITERATIONS: usize = 200;

    fn allow_cfg() -> SpawnConfig<'static> {
        SpawnConfig {
            args: &["hook", "claude-code"],
            stdin: super::ALLOW_PAYLOAD,
            cwd: None,
            envs: &[],
        }
    }

    fn ptuf_tempfile_names() -> BTreeSet<String> {
        std::fs::read_dir(std::env::temp_dir())
            .expect("read temp_dir")
            .filter_map(Result::ok)
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                name.starts_with("ptuf").then_some(name)
            })
            .collect()
    }

    #[test]
    #[ignore = "heavy E2E; run via `make e2e`"]
    fn repeated_hook_invocations_do_not_leak_test_process_fds() {
        // Warm-up: first spawn primes lazy resources so the diff
        // below measures only steady-state behaviour.
        let warm = spawn(&allow_cfg());
        assert_eq!(warm.code, 0, "warm-up: {}", warm.stderr_string());

        let before = open_fd_count().expect("fd count before");
        for i in 0..ITERATIONS {
            let r = spawn(&allow_cfg());
            assert_eq!(
                r.code,
                0,
                "iteration {i} exited {}, stderr={}",
                r.code,
                r.stderr_string()
            );
        }
        let after = open_fd_count().expect("fd count after");
        assert!(
            after <= before,
            "fd leak in test process: before={before} after={after}"
        );
    }

    #[test]
    #[ignore = "heavy E2E; run via `make e2e`"]
    fn repeated_hook_invocations_do_not_create_orphan_tempfiles() {
        let before = ptuf_tempfile_names();
        for _ in 0..ITERATIONS {
            let r = spawn(&allow_cfg());
            assert_eq!(r.code, 0);
        }
        let after = ptuf_tempfile_names();
        let leaked: Vec<_> = after.difference(&before).collect();
        assert!(
            leaked.is_empty(),
            "orphan ptuf tempfiles after {ITERATIONS} spawns: {leaked:?}"
        );
    }

    #[test]
    #[ignore = "heavy E2E; run via `make e2e`"]
    fn audit_writer_releases_file_handle_after_each_spawn() {
        use super::common::{LayerYaml, as_env_refs, enforce_audit_yaml, envs_for, full_stack};

        let fix = full_stack(LayerYaml::empty());
        std::fs::write(
            fix.repo_root.join(".ptuf.yaml"),
            enforce_audit_yaml(&fix.audit_path),
        )
        .expect("write project yaml");

        let envs = envs_for(&fix);
        let env_refs = as_env_refs(&envs);

        for _ in 0..100 {
            let r = spawn(&SpawnConfig {
                args: &["hook", "claude-code"],
                stdin: super::DENY_PAYLOAD,
                cwd: Some(&fix.repo_root),
                envs: &env_refs,
            });
            assert_eq!(r.code, 2, "deny expected: {}", r.stderr_string());
        }

        // If ptuf had left the audit file open under flock, the
        // re-open below would block or fail. Successful truncate
        // confirms the lock was released after each spawn.
        let reopened = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .truncate(true)
            .open(&fix.audit_path);
        assert!(
            reopened.is_ok(),
            "audit file not reopenable after 100 spawns: {:?}",
            reopened.err()
        );
    }

    #[test]
    #[ignore = "heavy E2E; run via `make e2e`"]
    fn child_process_does_not_persist_after_wait() {
        use std::process::{Command, Stdio};

        let mut child = Command::new(env!("CARGO_BIN_EXE_ptuf"))
            .args(["hook", "claude-code"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn ptuf");
        let pid = child.id();
        {
            use std::io::Write;
            let mut sin = child.stdin.take().expect("stdin");
            sin.write_all(super::ALLOW_PAYLOAD).expect("write stdin");
        }
        let _ = child.wait_with_output().expect("wait");
        // `wait_with_output` reaps the child; after this point
        // /proc/<pid> may still exist briefly as a zombie record
        // for the kernel scheduler, but once we observe the exit
        // status the process directory should be gone.
        let proc_entry = std::path::Path::new("/proc").join(pid.to_string());
        assert!(
            !proc_entry.exists(),
            "child process {pid} not reaped: {proc_entry:?} still present"
        );
    }
}

// ---------------------------------------------------------------------
// Axis 2: large-input boundary
// ---------------------------------------------------------------------

mod giant_input {
    use super::common::{
        LayerYaml, MAX_STDIN, SpawnConfig, as_env_refs, envs_for, full_stack, spawn,
    };
    use std::time::Duration;

    /// 8 MiB exactly: should NOT trip the size guard. The body may
    /// still be rejected as malformed JSON (the spaces after the
    /// envelope make it invalid JSON), but the `exceeds` message
    /// must not appear.
    #[test]
    #[ignore = "heavy E2E; run via `make e2e`"]
    fn hook_accepts_stdin_at_exactly_8mb() {
        let mut payload = Vec::with_capacity(MAX_STDIN);
        payload.extend_from_slice(super::ALLOW_PAYLOAD);
        payload.resize(MAX_STDIN, b' ');
        assert_eq!(payload.len(), MAX_STDIN);

        let r = spawn(&SpawnConfig {
            args: &["hook", "claude-code"],
            stdin: &payload,
            cwd: None,
            envs: &[],
        });
        let stderr = r.stderr_string();
        assert!(
            !stderr.contains("hook payload exceeds"),
            "size guard fired at exact limit: stderr={stderr}"
        );
        assert!(r.elapsed < Duration::from_secs(10), "took {:?}", r.elapsed);
    }

    /// 8 MiB + 1: must be rejected by the size guard with the
    /// `invalid-payload` rule and exit 2.
    #[test]
    #[ignore = "heavy E2E; run via `make e2e`"]
    fn hook_rejects_stdin_at_8mb_plus_one() {
        let payload = vec![b' '; MAX_STDIN + 1];
        let r = spawn(&SpawnConfig {
            args: &["hook", "claude-code"],
            stdin: &payload,
            cwd: None,
            envs: &[],
        });
        assert_eq!(r.code, 2, "stderr={}", r.stderr_string());
        let stderr = r.stderr_string();
        assert!(
            stderr.contains("hook payload exceeds"),
            "missing size guard message in stderr: {stderr}"
        );
        let stdout = r.stdout_string();
        assert!(
            stdout.contains("\"permissionDecision\":\"deny\""),
            "stdout did not carry deny JSON: {stdout}"
        );
    }

    #[test]
    #[ignore = "heavy E2E; run via `make e2e`"]
    fn check_handles_1000_stage_pipeline_within_budget() {
        let mut cmd = String::with_capacity(16 * 1000);
        for i in 0..1000 {
            if i > 0 {
                cmd.push_str(" | ");
            }
            cmd.push_str("cmd");
            cmd.push_str(&i.to_string());
            cmd.push_str(" arg");
            cmd.push_str(&i.to_string());
        }
        let r = spawn(&SpawnConfig {
            args: &["check", "--tool", "Bash", &cmd],
            stdin: &[],
            cwd: None,
            envs: &[],
        });
        // exit 0 (allow) or 2 (deny). Either is fine; we are
        // verifying the bash parser stays responsive.
        assert!(
            r.code == 0 || r.code == 2,
            "unexpected exit {}: stderr={}",
            r.code,
            r.stderr_string()
        );
        assert!(r.elapsed < Duration::from_secs(30), "took {:?}", r.elapsed);
        assert!(
            !r.stderr_string().to_lowercase().contains("panicked"),
            "panic in parser: {}",
            r.stderr_string()
        );
    }

    #[test]
    #[ignore = "heavy E2E; run via `make e2e`"]
    fn hook_handles_huge_command_string_inside_tool_input() {
        // 1 MiB of payload body, well within the 8 MiB ceiling but
        // large enough to stress redaction / facts extraction.
        let mut body = String::with_capacity(1_100_000);
        body.push_str(r#"{"tool_name":"Bash","tool_input":{"command":"echo "#);
        body.extend(std::iter::repeat_n('x', 1_000_000));
        body.push_str(r#""}}"#);

        let r = spawn(&SpawnConfig {
            args: &["hook", "claude-code"],
            stdin: body.as_bytes(),
            cwd: None,
            envs: &[],
        });
        assert!(
            r.code == 0 || r.code == 2,
            "unexpected exit {}: stderr={}",
            r.code,
            r.stderr_string()
        );
        assert!(r.elapsed < Duration::from_secs(10), "took {:?}", r.elapsed);
    }

    /// 100 plugins + 100 allowlists. Plan called for 1000 each but
    /// `make e2e` keeps a 60 s budget for the full axis; 100 is
    /// already a 10× jump over anything contracts.rs exercises.
    #[test]
    #[ignore = "heavy E2E; run via `make e2e`"]
    fn config_with_many_allowlists_and_plugin_paths_loads() {
        const N: usize = 100;

        let mut plugin_files = Vec::with_capacity(N);
        for i in 0..N {
            let name = format!("p{i}.yaml");
            let body = format!(
                "apiVersion: ptuf.dev/v1\nkind: Plugin\nmetadata:\n  name: pack.p{i}\nrules:\n  - id: pack.p{i}.noop\n    severity: low\n    defaultDecision: monitor\n    when:\n      tool: NoSuchTool{i}\n    reason: noop-{i}\n"
            );
            plugin_files.push((name, body));
        }

        let mut project_yaml = String::from("version: 1\nmode: enforce\nallowlists:\n");
        for i in 0..N {
            project_yaml.push_str(&format!(
                "  - id: allow-{i}\n    appliesTo:\n      rules: [core.git.reset-hard]\n    when:\n      shell.argv:\n        headAny: [git]\n"
            ));
        }
        project_yaml.push_str("plugins:\n");
        for i in 0..N {
            project_yaml.push_str(&format!("  - path: .ptuf/plugins/p{i}.yaml\n"));
        }

        let fix = full_stack(LayerYaml {
            project: Some(project_yaml),
            plugins: plugin_files,
            ..LayerYaml::empty()
        });

        let envs = envs_for(&fix);
        let env_refs = as_env_refs(&envs);
        let r = spawn(&SpawnConfig {
            args: &["hook", "claude-code"],
            stdin: super::ALLOW_PAYLOAD,
            cwd: Some(&fix.repo_root),
            envs: &env_refs,
        });
        assert!(
            r.code == 0 || r.code == 2,
            "unexpected exit {}: stderr={}",
            r.code,
            r.stderr_string()
        );
        assert!(
            !r.stderr_string().contains("core.engine.policy-load-failed"),
            "policy load failed at N={N}: {}",
            r.stderr_string()
        );
        assert!(r.elapsed < Duration::from_mins(1), "took {:?}", r.elapsed);
    }
}

// ---------------------------------------------------------------------
// Axis 3: sequential / concurrent hook invocations
// ---------------------------------------------------------------------

mod concurrent {
    use super::common::{
        LayerYaml, SpawnConfig, as_env_refs, enforce_audit_yaml, envs_for, full_stack, spawn,
    };
    use std::time::Duration;

    const SEQ_ITERATIONS: usize = 200;
    const WORKERS: usize = 10;
    const PER_WORKER: usize = 100;

    #[test]
    #[ignore = "heavy E2E; run via `make e2e`"]
    fn sequential_invocations_complete_under_time_budget() {
        let started = std::time::Instant::now();
        for i in 0..SEQ_ITERATIONS {
            let r = spawn(&SpawnConfig {
                args: &["hook", "claude-code"],
                stdin: super::ALLOW_PAYLOAD,
                cwd: None,
                envs: &[],
            });
            assert_eq!(r.code, 0, "iter {i}: stderr={}", r.stderr_string());
        }
        let total = started.elapsed();
        let per = total / SEQ_ITERATIONS as u32;
        assert!(
            total < Duration::from_mins(2),
            "{SEQ_ITERATIONS} iters took {total:?} (avg {per:?})"
        );
    }

    #[test]
    #[ignore = "heavy E2E; run via `make e2e`"]
    fn ten_workers_hundred_iterations_each_complete_without_crash() {
        std::thread::scope(|s| {
            let handles: Vec<_> = (0..WORKERS)
                .map(|w| {
                    s.spawn(move || {
                        for i in 0..PER_WORKER {
                            let r = spawn(&SpawnConfig {
                                args: &["hook", "claude-code"],
                                stdin: super::ALLOW_PAYLOAD,
                                cwd: None,
                                envs: &[],
                            });
                            assert_eq!(
                                r.code,
                                0,
                                "worker {w} iter {i}: stderr={}",
                                r.stderr_string()
                            );
                        }
                    })
                })
                .collect();
            for h in handles {
                h.join().expect("worker panicked");
            }
        });
    }

    /// Same audit path, 10 workers × 100 deny each. Every line must
    /// be valid JSON (corruption from interleaved writes would
    /// fail parse) and the line count must match exactly. Upper
    /// bound 120 s because flock serialises the writers.
    #[test]
    #[ignore = "heavy E2E; run via `make e2e`"]
    fn concurrent_writers_produce_well_formed_jsonl_lines() {
        let fix = full_stack(LayerYaml::empty());
        std::fs::write(
            fix.repo_root.join(".ptuf.yaml"),
            enforce_audit_yaml(&fix.audit_path),
        )
        .expect("write project yaml");
        let envs = envs_for(&fix);
        let env_refs = as_env_refs(&envs);
        let cwd: &std::path::Path = &fix.repo_root;
        let env_refs: &[_] = &env_refs;

        let started = std::time::Instant::now();
        std::thread::scope(|s| {
            let handles: Vec<_> = (0..WORKERS)
                .map(|w| {
                    s.spawn(move || {
                        for i in 0..PER_WORKER {
                            let r = spawn(&SpawnConfig {
                                args: &["hook", "claude-code"],
                                stdin: super::DENY_PAYLOAD,
                                cwd: Some(cwd),
                                envs: env_refs,
                            });
                            assert_eq!(
                                r.code,
                                2,
                                "worker {w} iter {i}: stderr={}",
                                r.stderr_string()
                            );
                        }
                    })
                })
                .collect();
            for h in handles {
                h.join().expect("worker panicked");
            }
        });
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_mins(2),
            "concurrent run took {elapsed:?}"
        );

        let body = std::fs::read_to_string(&fix.audit_path).expect("read audit file");
        assert!(
            body.ends_with('\n'),
            "audit JSONL does not end with newline (last 32 bytes: {:?})",
            &body[body.len().saturating_sub(32)..]
        );
        let lines: Vec<&str> = body.lines().collect();
        let expected = WORKERS * PER_WORKER;
        assert_eq!(
            lines.len(),
            expected,
            "expected {expected} lines, got {} (first line: {:?})",
            lines.len(),
            lines.first()
        );
        for (idx, line) in lines.iter().enumerate() {
            let v: serde_json::Value = serde_json::from_str(line).unwrap_or_else(|e| {
                panic!("line {idx} not valid JSON (interleaved write?): {e}\nline={line:?}")
            });
            assert_eq!(v["event"], "PreToolUse", "line {idx}: {line}");
            assert_eq!(v["decision"], "deny", "line {idx}: {line}");
            for key in [
                "schemaVersion",
                "timestamp",
                "event",
                "tool",
                "decision",
                "commandRedacted",
                "mode",
                "agent",
            ] {
                assert!(
                    v.get(key).is_some(),
                    "line {idx} missing required field {key}: {line}"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------
// Axis 4: full 4-layer config stack + plugin + audit end-to-end
// ---------------------------------------------------------------------

mod full_config_stack {
    use super::common::{
        LayerYaml, SpawnConfig, as_env_refs, enforce_audit_yaml, envs_for, full_stack, spawn,
    };

    /// System: mode: monitor.
    /// User: empty.
    /// Project: audit on with includeAllowed.
    /// Project-local: mode: enforce (final override).
    /// An allow payload must produce one JSONL row whose `mode` is
    /// `enforce`, proving the layers merged in priority order.
    #[test]
    #[ignore = "heavy E2E; run via `make e2e`"]
    fn four_layer_config_merges_in_documented_priority_order() {
        let fix = full_stack(LayerYaml::empty());
        let audit = fix.audit_path.display().to_string();
        std::fs::write(
            fix.etc_dir.join("policy.yaml"),
            "version: 1\nmode: monitor\n",
        )
        .expect("system yaml");
        std::fs::write(fix.config_dir.join("config.yaml"), "version: 1\n").expect("user yaml");
        std::fs::write(
            fix.repo_root.join(".ptuf.yaml"),
            format!(
                "version: 1\naudit:\n  path: {audit}\n  enabled: true\n  includeAllowed: true\n  includeDenied: true\n"
            ),
        )
        .expect("project yaml");
        std::fs::write(
            fix.repo_root.join(".ptuf.local.yaml"),
            "version: 1\nmode: enforce\n",
        )
        .expect("project_local yaml");

        let envs = envs_for(&fix);
        let env_refs = as_env_refs(&envs);
        let r = spawn(&SpawnConfig {
            args: &["hook", "claude-code"],
            stdin: super::ALLOW_PAYLOAD,
            cwd: Some(&fix.repo_root),
            envs: &env_refs,
        });
        assert_eq!(r.code, 0, "stderr={}", r.stderr_string());

        let body = std::fs::read_to_string(&fix.audit_path).expect("read audit");
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 1, "expected 1 audit line, body={body}");
        let v: serde_json::Value = serde_json::from_str(lines[0]).expect("valid JSON");
        assert_eq!(v["mode"], "enforce", "merged mode wrong: {}", lines[0]);
        assert_eq!(v["decision"], "allow", "decision wrong: {}", lines[0]);
    }

    #[test]
    #[ignore = "heavy E2E; run via `make e2e`"]
    fn plugin_loaded_through_layered_config_evaluates_against_payload() {
        let plugin_yaml = String::from(
            "apiVersion: ptuf.dev/v1\nkind: Plugin\nmetadata:\n  name: pack.no-curl\nrules:\n  - id: pack.no-curl.block\n    severity: high\n    defaultDecision: deny\n    when:\n      shell.argv:\n        headAny: [curl]\n    reason: curl is blocked by plugin\n",
        );
        let fix = full_stack(LayerYaml {
            plugins: vec![("no-curl.yaml".to_string(), plugin_yaml)],
            ..LayerYaml::empty()
        });
        std::fs::write(
            fix.repo_root.join(".ptuf.yaml"),
            "version: 1\nplugins:\n  - path: .ptuf/plugins/no-curl.yaml\n",
        )
        .expect("project yaml");

        let envs = envs_for(&fix);
        let env_refs = as_env_refs(&envs);
        let payload =
            br#"{"tool_name":"Bash","tool_input":{"command":"curl https://example.com"}}"#;
        let r = spawn(&SpawnConfig {
            args: &["hook", "claude-code"],
            stdin: payload,
            cwd: Some(&fix.repo_root),
            envs: &env_refs,
        });
        assert_eq!(r.code, 2, "stderr={}", r.stderr_string());
        let stderr = r.stderr_string();
        assert!(
            stderr.contains("pack.no-curl.block"),
            "plugin rule_id missing in stderr: {stderr}"
        );
    }

    #[test]
    #[ignore = "heavy E2E; run via `make e2e`"]
    fn audit_path_from_config_is_honored_end_to_end() {
        let fix = full_stack(LayerYaml::empty());
        let custom_audit = fix.root.path().join("custom-audit.jsonl");
        std::fs::write(
            fix.repo_root.join(".ptuf.yaml"),
            enforce_audit_yaml(&custom_audit),
        )
        .expect("project yaml");

        let envs = envs_for(&fix);
        let env_refs = as_env_refs(&envs);
        let r = spawn(&SpawnConfig {
            args: &["hook", "claude-code"],
            stdin: super::DENY_PAYLOAD,
            cwd: Some(&fix.repo_root),
            envs: &env_refs,
        });
        assert_eq!(r.code, 2, "stderr={}", r.stderr_string());
        assert!(
            custom_audit.exists(),
            "configured audit path was not written: {custom_audit:?}"
        );
        // The default audit path (~/.local/share/ptuf/audit.jsonl)
        // under our sandbox HOME must NOT exist — the project-layer
        // override should fully redirect the writer.
        let default_audit = fix.root.path().join(".local/share/ptuf/audit.jsonl");
        assert!(
            !default_audit.exists(),
            "default audit path leaked despite override: {default_audit:?}"
        );
    }
}

// ---------------------------------------------------------------------
// Axis 5: cross-adapter parity — every agent's native shape end-to-end
// ---------------------------------------------------------------------

/// Drives all five adapters (claude-code / codex / copilot / kiro /
/// cline) through real process boundaries in their native payload
/// shapes and pins the per-agent exit-code and stdout/stderr contract
/// from `docs/design/cli-and-hooks.md`. The leak / concurrent / giant
/// axes only ever exercise `claude-code`; this axis guards the other
/// four against silent contract drift.
mod adapter_parity {
    use super::common::{SpawnConfig, SpawnOutcome, assert_clean_exit, spawn};

    const COPILOT_DENY: &[u8] = br#"{"toolName":"bash","toolArgs":{"command":"rm -rf /"}}"#;
    const COPILOT_ALLOW: &[u8] = br#"{"toolName":"bash","toolArgs":{"command":"ls"}}"#;
    const KIRO_DENY: &[u8] = br#"{"hook_event_name":"preToolUse","tool_name":"shell","tool_input":{"command":"rm -rf /"}}"#;
    const KIRO_ALLOW: &[u8] = br#"{"hook_event_name":"preToolUse","tool_name":"shell","tool_input":{"command":"ls"}}"#;
    const CLINE_DENY: &[u8] = br#"{"hookName":"tool_call","tool_call":{"id":"c1","name":"execute_command","input":{"command":"rm -rf /"}}}"#;
    const CLINE_ALLOW: &[u8] = br#"{"hookName":"tool_call","tool_call":{"id":"c1","name":"execute_command","input":{"command":"ls"}}}"#;
    const CLINE_LEGACY_DENY: &[u8] = br#"{"hookName":"PreToolUse","preToolUse":{"toolName":"execute_command","parameters":{"command":"rm -rf /"}}}"#;

    fn hook(agent: &str, stdin: &[u8]) -> SpawnOutcome {
        spawn(&SpawnConfig {
            args: &["hook", agent],
            stdin,
            cwd: None,
            envs: &[],
        })
    }

    #[test]
    #[ignore = "heavy E2E; run via `make e2e`"]
    fn every_adapter_denies_destructive_rm_per_contract() {
        // Claude Code: exit 2, hookSpecificOutput-wrapped deny JSON.
        let r = hook("claude-code", super::DENY_PAYLOAD);
        assert_clean_exit(&r);
        assert_eq!(r.code, 2, "claude-code deny: {}", r.stderr_string());
        let out = r.stdout_string();
        assert!(
            out.contains(r#""permissionDecision":"deny""#),
            "claude-code stdout: {out}"
        );
        assert!(out.contains("hookSpecificOutput"), "claude-code must wrap: {out}");

        // Codex: same shape and exit as Claude Code.
        let r = hook("codex", super::DENY_PAYLOAD);
        assert_clean_exit(&r);
        assert_eq!(r.code, 2, "codex deny: {}", r.stderr_string());
        let out = r.stdout_string();
        assert!(
            out.contains(r#""permissionDecision":"deny""#),
            "codex stdout: {out}"
        );
        assert!(out.contains("hookSpecificOutput"), "codex must wrap: {out}");

        // Copilot: exit 0 (a non-zero exit would be read as a hook
        // failure and fail open), bare envelope with no wrap.
        let r = hook("copilot", COPILOT_DENY);
        assert_clean_exit(&r);
        assert_eq!(r.code, 0, "copilot deny must exit 0: {}", r.stderr_string());
        let out = r.stdout_string();
        assert!(
            out.contains(r#""permissionDecision":"deny""#),
            "copilot stdout: {out}"
        );
        assert!(!out.contains("hookSpecificOutput"), "copilot must be bare: {out}");

        // Kiro: exit 2, no JSON envelope — reason on stderr only.
        let r = hook("kiro", KIRO_DENY);
        assert_clean_exit(&r);
        assert_eq!(r.code, 2, "kiro deny: {}", r.stderr_string());
        assert!(
            r.stdout_string().trim().is_empty(),
            "kiro stdout must be empty: {}",
            r.stdout_string()
        );
        assert!(
            !r.stderr_string().trim().is_empty(),
            "kiro deny reason must be on stderr"
        );

        // Cline: exit 0, cancel-envelope JSON on stdout.
        let r = hook("cline", CLINE_DENY);
        assert_clean_exit(&r);
        assert_eq!(r.code, 0, "cline deny must exit 0: {}", r.stderr_string());
        let out = r.stdout_string();
        assert!(out.contains(r#""cancel":true"#), "cline stdout: {out}");
    }

    #[test]
    #[ignore = "heavy E2E; run via `make e2e`"]
    fn every_adapter_allows_benign_ls_per_contract() {
        // Claude Code / Codex: exit 0, empty stdout.
        for agent in ["claude-code", "codex"] {
            let r = hook(agent, super::ALLOW_PAYLOAD);
            assert_clean_exit(&r);
            assert_eq!(r.code, 0, "{agent} allow: {}", r.stderr_string());
            assert!(
                r.stdout_string().trim().is_empty(),
                "{agent} allow stdout must be empty: {}",
                r.stdout_string()
            );
        }

        // Copilot: exit 0, empty stdout.
        let r = hook("copilot", COPILOT_ALLOW);
        assert_clean_exit(&r);
        assert_eq!(r.code, 0, "copilot allow: {}", r.stderr_string());
        assert!(
            r.stdout_string().trim().is_empty(),
            "copilot allow stdout must be empty: {}",
            r.stdout_string()
        );

        // Kiro: exit 0, empty stdout AND empty stderr.
        let r = hook("kiro", KIRO_ALLOW);
        assert_clean_exit(&r);
        assert_eq!(r.code, 0, "kiro allow: {}", r.stderr_string());
        assert!(
            r.stdout_string().trim().is_empty(),
            "kiro allow stdout: {}",
            r.stdout_string()
        );
        assert!(
            r.stderr_string().trim().is_empty(),
            "kiro allow stderr must be empty: {}",
            r.stderr_string()
        );

        // Cline: exit 0, empty-object `{}` on stdout.
        let r = hook("cline", CLINE_ALLOW);
        assert_clean_exit(&r);
        assert_eq!(r.code, 0, "cline allow: {}", r.stderr_string());
        assert_eq!(
            r.stdout_string().trim(),
            "{}",
            "cline allow must emit an empty object"
        );
    }

    #[test]
    #[ignore = "heavy E2E; run via `make e2e`"]
    fn copilot_normalizes_camelcase_string_and_vscode_shapes() {
        // All three documented Copilot input shapes must reach the
        // same destructive-rm deny: object toolArgs (camelCase), a
        // JSON-encoded string toolArgs, and the VS Code snake_case
        // tool_input form.
        let shapes: [(&str, &[u8]); 3] = [
            ("camelCase object toolArgs", COPILOT_DENY),
            (
                "JSON-encoded string toolArgs",
                br#"{"toolName":"bash","toolArgs":"{\"command\":\"rm -rf /\"}"}"#,
            ),
            (
                "VS Code snake_case tool_input",
                br#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#,
            ),
        ];
        for (label, payload) in shapes {
            let r = hook("copilot", payload);
            assert_clean_exit(&r);
            assert_eq!(
                r.code, 0,
                "{label}: copilot must exit 0: {}",
                r.stderr_string()
            );
            let out = r.stdout_string();
            assert!(
                out.contains(r#""permissionDecision":"deny""#),
                "{label}: stdout {out}"
            );
            assert!(!out.contains("hookSpecificOutput"), "{label}: must be bare: {out}");
        }
    }

    #[test]
    #[ignore = "heavy E2E; run via `make e2e`"]
    fn cline_normalizes_sdk_and_legacy_envelopes() {
        // SDK tool_call envelope and legacy preToolUse envelope must
        // both reach the same deny + cancel JSON.
        for (label, payload) in [
            ("SDK tool_call envelope", CLINE_DENY),
            ("legacy preToolUse envelope", CLINE_LEGACY_DENY),
        ] {
            let r = hook("cline", payload);
            assert_clean_exit(&r);
            assert_eq!(
                r.code, 0,
                "{label}: cline must exit 0: {}",
                r.stderr_string()
            );
            let out = r.stdout_string();
            assert!(out.contains(r#""cancel":true"#), "{label}: stdout {out}");
        }
    }

    #[test]
    #[ignore = "heavy E2E; run via `make e2e`"]
    fn kiro_rejects_malformed_events_fail_closed() {
        // Wrong hook_event_name → core.engine.invalid-payload deny.
        let r = hook(
            "kiro",
            br#"{"hook_event_name":"postToolUse","tool_name":"shell","tool_input":{"command":"ls"}}"#,
        );
        assert_clean_exit(&r);
        assert_eq!(
            r.code, 2,
            "kiro wrong-event must fail closed: {}",
            r.stderr_string()
        );
        assert!(
            r.stdout_string().trim().is_empty(),
            "kiro fail-closed stdout must be empty: {}",
            r.stdout_string()
        );
        assert!(
            !r.stderr_string().trim().is_empty(),
            "kiro fail-closed reason must be on stderr"
        );

        // Missing tool_name → same fail-closed path.
        let r = hook(
            "kiro",
            br#"{"hook_event_name":"preToolUse","tool_input":{"command":"ls"}}"#,
        );
        assert_clean_exit(&r);
        assert_eq!(
            r.code, 2,
            "kiro missing-tool_name must fail closed: {}",
            r.stderr_string()
        );
    }

    #[test]
    #[ignore = "heavy E2E; run via `make e2e`"]
    fn fifty_sequential_invocations_per_adapter_stay_clean() {
        const N: usize = 50;
        let allow: [(&str, &[u8]); 5] = [
            ("claude-code", super::ALLOW_PAYLOAD),
            ("codex", super::ALLOW_PAYLOAD),
            ("copilot", COPILOT_ALLOW),
            ("kiro", KIRO_ALLOW),
            ("cline", CLINE_ALLOW),
        ];
        for (agent, payload) in allow {
            for i in 0..N {
                let r = hook(agent, payload);
                assert_clean_exit(&r);
                assert_eq!(r.code, 0, "{agent} iter {i}: {}", r.stderr_string());
            }
        }
    }
}

// ---------------------------------------------------------------------
// Axis 6: pathological input — the primary crash / hang / delay probe
// ---------------------------------------------------------------------

/// Feeds malformed, oversized, and deeply nested payloads through real
/// process boundaries. Deep nesting is *expected* to be rejected
/// safely — serde_json caps recursion at 128 and the shell parser is
/// depth-bounded — so this axis verifies that the rejection holds at a
/// process boundary (no SIGSEGV, no infinite loop) rather than
/// trusting it. Every case asserts the shared fail-closed contract:
/// no crash, no hang, a documented exit code, and an answer within
/// budget.
mod pathological_input {
    use super::common::{MAX_STDIN, SpawnConfig, SpawnOutcome, assert_clean_exit, spawn};
    use std::time::Duration;

    /// Upper bound for one ordinary pathological call. Generous —
    /// `make e2e` builds debug and each case spawns a subprocess — but
    /// far below the 60 s hang timeout so a genuine slowdown still
    /// fails as a *delay*.
    const PER_CALL_BUDGET: Duration = Duration::from_secs(15);

    /// Looser bound for the two multi-megabyte cases (50k secret
    /// tokens, near-8 MiB pipeline). Still below the hang timeout, so
    /// an unbounded loop is caught, but tolerant of honest linear work
    /// over millions of tokens in a debug build.
    const HEAVY_BUDGET: Duration = Duration::from_secs(45);

    const TRUNCATED: &[u8] = br#"{"tool_name":"Bash","tool_input":{"command":"ls"#;

    fn run(args: &[&str], stdin: &[u8]) -> SpawnOutcome {
        spawn(&SpawnConfig {
            args,
            stdin,
            cwd: None,
            envs: &[],
        })
    }

    fn non_utf8_blob() -> Vec<u8> {
        let mut v = Vec::with_capacity(8192);
        for _ in 0..2048 {
            v.extend_from_slice(&[0xFF, 0xFE, 0x80, 0xC0]);
        }
        v
    }

    fn nul_blob() -> Vec<u8> {
        let mut v = super::ALLOW_PAYLOAD.to_vec();
        v.extend(std::iter::repeat_n(0u8, 4096));
        v
    }

    /// `hook claude-code` and `check` answer allow with exit 0 and deny
    /// with exit 2; no other code is part of the contract. Combined
    /// with `assert_clean_exit` this is the full "no crash, no hang,
    /// fail closed, no delay" check.
    #[track_caller]
    fn assert_fail_closed(r: &SpawnOutcome, label: &str, budget: Duration) {
        assert_clean_exit(r);
        assert!(
            r.code == 0 || r.code == 2,
            "{label}: undocumented exit {} (stderr={})",
            r.code,
            r.stderr_string()
        );
        assert!(
            r.elapsed < budget,
            "{label}: took {:?}, over budget {budget:?}",
            r.elapsed
        );
        let stderr = r.stderr_string();
        assert!(
            !stderr.to_lowercase().contains("panicked"),
            "{label}: panic leaked to stderr: {stderr}"
        );
    }

    #[test]
    #[ignore = "heavy E2E; run via `make e2e`"]
    fn non_utf8_stdin_fails_closed() {
        let r = run(&["hook", "claude-code"], &non_utf8_blob());
        assert_fail_closed(&r, "non-utf8 stdin", PER_CALL_BUDGET);
        assert_eq!(r.code, 2, "invalid bytes must fail closed to deny");
    }

    #[test]
    #[ignore = "heavy E2E; run via `make e2e`"]
    fn embedded_nul_bytes_fail_closed() {
        let r = run(&["hook", "claude-code"], &nul_blob());
        assert_fail_closed(&r, "embedded NUL", PER_CALL_BUDGET);
        assert_eq!(r.code, 2, "trailing NUL bytes must fail closed to deny");
    }

    #[test]
    #[ignore = "heavy E2E; run via `make e2e`"]
    fn deeply_nested_json_fails_closed_without_stack_overflow() {
        const DEPTH: usize = 20_000;
        let mut payload = String::with_capacity(DEPTH * 5 + DEPTH + 1);
        for _ in 0..DEPTH {
            payload.push_str("{\"a\":");
        }
        payload.push('1');
        for _ in 0..DEPTH {
            payload.push('}');
        }
        let r = run(&["hook", "claude-code"], payload.as_bytes());
        // serde_json's recursion limit rejects this far short of any
        // stack exhaustion; the point is rejection without a SIGSEGV.
        assert_fail_closed(&r, "deeply nested JSON", PER_CALL_BUDGET);
        assert_eq!(r.code, 2, "over-nested JSON must fail closed to deny");
    }

    #[test]
    #[ignore = "heavy E2E; run via `make e2e`"]
    fn deeply_nested_bash_substitution_stays_bounded() {
        const DEPTH: usize = 5_000;
        let mut cmd = String::with_capacity(DEPTH * 7 + DEPTH + 1);
        for _ in 0..DEPTH {
            cmd.push_str("$(echo ");
        }
        cmd.push('x');
        for _ in 0..DEPTH {
            cmd.push(')');
        }
        // Decision (allow/deny) is irrelevant here — the probe is that
        // the shell parser's bounded depth holds without a crash.
        let r = run(&["check", "--tool", "Bash", &cmd], &[]);
        assert_fail_closed(&r, "deeply nested bash substitution", PER_CALL_BUDGET);
    }

    #[test]
    #[ignore = "heavy E2E; run via `make e2e`"]
    fn fifty_thousand_secret_tokens_redact_within_budget() {
        const TOKENS: usize = 50_000;
        let token = " AKIAIOSFODNN7EXAMPLE aws_secret=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY";
        let mut cmd = String::with_capacity(TOKENS * token.len() + 16);
        cmd.push_str("rm -rf / #");
        for _ in 0..TOKENS {
            cmd.push_str(token);
        }
        let mut payload = String::with_capacity(cmd.len() + 64);
        payload.push_str(r#"{"tool_name":"Bash","tool_input":{"command":""#);
        payload.push_str(&cmd);
        payload.push_str(r#""}}"#);
        let r = run(&["hook", "claude-code"], payload.as_bytes());
        assert_fail_closed(&r, "50k secret tokens", HEAVY_BUDGET);
    }

    #[test]
    #[ignore = "heavy E2E; run via `make e2e`"]
    fn truncated_json_envelope_fails_closed() {
        let r = run(&["hook", "claude-code"], TRUNCATED);
        assert_fail_closed(&r, "truncated JSON", PER_CALL_BUDGET);
        assert_eq!(r.code, 2, "truncated envelope must fail closed to deny");
    }

    #[test]
    #[ignore = "heavy E2E; run via `make e2e`"]
    fn near_8mib_pipeline_payload_stays_responsive() {
        let prefix = br#"{"tool_name":"Bash","tool_input":{"command":""#;
        let suffix = br#""}}"#;
        let budget = MAX_STDIN - prefix.len() - suffix.len() - 64;
        let stage = "echo x|";
        let stages = budget / stage.len();
        let mut cmd = String::with_capacity(stages * stage.len() + 8);
        for _ in 0..stages {
            cmd.push_str(stage);
        }
        cmd.push_str("echo x");
        let mut payload = Vec::with_capacity(MAX_STDIN);
        payload.extend_from_slice(prefix);
        payload.extend_from_slice(cmd.as_bytes());
        payload.extend_from_slice(suffix);
        assert!(
            payload.len() <= MAX_STDIN,
            "payload {} exceeds stdin ceiling {MAX_STDIN}",
            payload.len()
        );
        let r = run(&["hook", "claude-code"], &payload);
        assert_fail_closed(&r, "near-8MiB pipeline", HEAVY_BUDGET);
    }

    #[test]
    #[ignore = "heavy E2E; run via `make e2e`"]
    fn repeated_malformed_input_does_not_degrade() {
        // Twenty rounds of the cheap malformed inputs back to back. A
        // per-spawn resource leak or super-linear slowdown would show
        // up as a budget breach on a late round. The two heavy cases
        // (50k secrets, near-8 MiB pipeline) are excluded to keep this
        // axis inside the `make e2e` time budget.
        const ROUNDS: usize = 20;
        let non_utf8 = non_utf8_blob();
        let nul = nul_blob();
        for round in 0..ROUNDS {
            for (label, stdin) in [
                ("non-utf8", non_utf8.as_slice()),
                ("nul", nul.as_slice()),
                ("truncated", TRUNCATED),
            ] {
                let r = run(&["hook", "claude-code"], stdin);
                let tag = format!("round {round} {label}");
                assert_fail_closed(&r, &tag, PER_CALL_BUDGET);
                assert_eq!(r.code, 2, "{tag}: must fail closed to deny");
            }
        }
    }
}
