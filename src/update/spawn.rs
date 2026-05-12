//! Process-spawning seam used by `ptuf update`.
//!
//! The trait lets unit tests inject a recording fake while production code
//! drives `std::process::Command` synchronously. Mirrors the
//! `Command::new(...).output()` pattern already used by
//! `src/audit/writer.rs:197` for `id -u`.

use std::io;
use std::process::Command;

#[derive(Debug)]
pub struct SpawnOutcome {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

pub trait Spawner {
    fn run(&self, program: &str, args: &[&str]) -> io::Result<SpawnOutcome>;
}

#[derive(Debug, Default)]
pub struct ProcessSpawner;

impl Spawner for ProcessSpawner {
    fn run(&self, program: &str, args: &[&str]) -> io::Result<SpawnOutcome> {
        let output = Command::new(program).args(args).output()?;
        Ok(SpawnOutcome {
            exit_code: output.status.code().unwrap_or(1),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}

#[cfg(test)]
pub mod testing {
    use std::cell::RefCell;
    use std::io;

    use super::{SpawnOutcome, Spawner};

    #[derive(Debug)]
    pub struct RecordedCall {
        pub program: String,
        pub args: Vec<String>,
    }

    pub struct RecordingSpawner {
        outcomes: RefCell<Vec<io::Result<SpawnOutcome>>>,
        calls: RefCell<Vec<RecordedCall>>,
    }

    impl RecordingSpawner {
        pub fn new(outcomes: Vec<io::Result<SpawnOutcome>>) -> Self {
            Self {
                outcomes: RefCell::new(outcomes),
                calls: RefCell::new(Vec::new()),
            }
        }

        pub fn calls(&self) -> Vec<RecordedCall> {
            self.calls
                .borrow()
                .iter()
                .map(|c| RecordedCall {
                    program: c.program.clone(),
                    args: c.args.clone(),
                })
                .collect()
        }
    }

    impl Spawner for RecordingSpawner {
        fn run(&self, program: &str, args: &[&str]) -> io::Result<SpawnOutcome> {
            self.calls.borrow_mut().push(RecordedCall {
                program: program.to_string(),
                args: args.iter().map(|s| (*s).to_string()).collect(),
            });
            let mut outcomes = self.outcomes.borrow_mut();
            if outcomes.is_empty() {
                return Err(io::Error::other("RecordingSpawner exhausted"));
            }
            outcomes.remove(0)
        }
    }

    pub fn ok(stdout: &str) -> io::Result<SpawnOutcome> {
        Ok(SpawnOutcome {
            exit_code: 0,
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        })
    }

    pub fn ok_with_stderr(exit_code: i32, stderr: &str) -> io::Result<SpawnOutcome> {
        Ok(SpawnOutcome {
            exit_code,
            stdout: Vec::new(),
            stderr: stderr.as_bytes().to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_spawner_returns_exit_code_and_streams() {
        let spawner = ProcessSpawner;
        let outcome = spawner.run("true", &[]).expect("true should run");
        assert_eq!(outcome.exit_code, 0);
        assert!(outcome.stdout.is_empty());
        assert!(outcome.stderr.is_empty());
    }

    #[test]
    fn process_spawner_propagates_nonzero_exit_code() {
        let spawner = ProcessSpawner;
        let outcome = spawner.run("false", &[]).expect("false should run");
        assert_eq!(outcome.exit_code, 1);
    }

    #[test]
    fn process_spawner_returns_io_error_when_program_missing() {
        let spawner = ProcessSpawner;
        let err = spawner
            .run("ptuf-nonexistent-binary-xyz", &[])
            .expect_err("missing program must surface as io::Error");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }
}
