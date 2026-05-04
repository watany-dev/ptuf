use std::io::{self, Read};
use std::process::ExitCode;

use ptuf::{Decision, HookInput, decide};

fn main() -> ExitCode {
    let mut buf = String::new();
    if io::stdin().read_to_string(&mut buf).is_err() {
        eprintln!("ptuf: failed to read stdin");
        return ExitCode::from(1);
    }

    let input: HookInput = match serde_json::from_str(&buf) {
        Ok(v) => v,
        Err(err) => {
            eprintln!("ptuf: invalid hook payload: {err}");
            return ExitCode::from(1);
        }
    };

    match decide(&input) {
        Decision::Allow => ExitCode::from(0),
        Decision::Deny { reason } => {
            eprintln!("{reason}");
            ExitCode::from(2)
        }
    }
}
