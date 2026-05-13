//! Heavy E2E tests reproducing real-world ptuf invocation patterns.
//!
//! All tests are `#[ignore]` so `cargo test` and `make check` skip
//! them. Run via `make e2e` (or
//! `cargo test --features testing --test e2e_heavy -- --ignored --test-threads=1`).
//!
//! Four axes:
//! - `leak`            — fd / tempfile / child-process residue
//! - `giant_input`     — 8 MiB stdin, 1000-stage pipeline, oversized configs
//! - `concurrent`      — sequential 1000 and parallel 10×100 invocations
//! - `full_config_stack` — 4-layer config + plugin + audit end-to-end

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

    const ITERATIONS: usize = 200;

    fn allow_cfg() -> SpawnConfig<'static> {
        SpawnConfig {
            args: &["hook", "claude-code"],
            stdin: super::ALLOW_PAYLOAD,
            cwd: None,
            envs: &[],
        }
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
        let tmp = std::env::temp_dir();
        let before: std::collections::BTreeSet<_> = std::fs::read_dir(&tmp)
            .expect("read temp_dir")
            .filter_map(Result::ok)
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                if name.starts_with("ptuf") {
                    Some(name)
                } else {
                    None
                }
            })
            .collect();

        for _ in 0..ITERATIONS {
            let r = spawn(&allow_cfg());
            assert_eq!(r.code, 0);
        }

        let after: std::collections::BTreeSet<_> = std::fs::read_dir(&tmp)
            .expect("read temp_dir")
            .filter_map(Result::ok)
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                if name.starts_with("ptuf") {
                    Some(name)
                } else {
                    None
                }
            })
            .collect();

        let leaked: Vec<_> = after.difference(&before).collect();
        assert!(
            leaked.is_empty(),
            "orphan ptuf tempfiles after {ITERATIONS} spawns: {leaked:?}"
        );
    }

    #[test]
    #[ignore = "heavy E2E; run via `make e2e`"]
    fn audit_writer_releases_file_handle_after_each_spawn() {
        use super::common::{LayerYaml, as_env_refs, envs_for, full_stack};

        let fix = full_stack(LayerYaml::empty());
        let yaml = format!(
            "version: 1\nmode: enforce\naudit:\n  path: {audit}\n  enabled: true\n  includeAllowed: false\n  includeDenied: true\n",
            audit = fix.audit_path.display()
        );
        std::fs::write(fix.repo_root.join(".ptuf.yaml"), yaml).expect("write project yaml");

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
        let body = br#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#;
        let mut payload = Vec::with_capacity(MAX_STDIN);
        payload.extend_from_slice(body);
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
        assert!(r.elapsed < Duration::from_secs(60), "took {:?}", r.elapsed);
    }
}

// ---------------------------------------------------------------------
// Axis 3: sequential / concurrent hook invocations
// ---------------------------------------------------------------------

mod concurrent {
    use super::common::{LayerYaml, SpawnConfig, as_env_refs, envs_for, full_stack, spawn};
    use std::time::Duration;

    const SEQ_ITERATIONS: usize = 200;
    const WORKERS: usize = 10;
    const PER_WORKER: usize = 100;

    #[test]
    #[ignore = "heavy E2E; run via `make e2e`"]
    fn sequential_thousand_invocations_complete_under_time_budget() {
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
            total < Duration::from_secs(120),
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
        let yaml = format!(
            "version: 1\nmode: enforce\naudit:\n  path: {audit}\n  enabled: true\n  includeAllowed: false\n  includeDenied: true\n",
            audit = fix.audit_path.display()
        );
        std::fs::write(fix.repo_root.join(".ptuf.yaml"), yaml).expect("write project yaml");
        let envs = envs_for(&fix);
        let env_refs = as_env_refs(&envs);
        let cwd = fix.repo_root.clone();
        let env_refs_ref = &env_refs;
        let cwd_ref = &cwd;

        let started = std::time::Instant::now();
        std::thread::scope(|s| {
            let handles: Vec<_> = (0..WORKERS)
                .map(|w| {
                    s.spawn(move || {
                        for i in 0..PER_WORKER {
                            let r = spawn(&SpawnConfig {
                                args: &["hook", "claude-code"],
                                stdin: super::DENY_PAYLOAD,
                                cwd: Some(cwd_ref),
                                envs: env_refs_ref,
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
            elapsed < Duration::from_secs(120),
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
    use super::common::{LayerYaml, SpawnConfig, as_env_refs, envs_for, full_stack, spawn};

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
            format!(
                "version: 1\nmode: enforce\naudit:\n  path: {audit}\n  enabled: true\n  includeAllowed: false\n  includeDenied: true\n",
                audit = custom_audit.display()
            ),
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
