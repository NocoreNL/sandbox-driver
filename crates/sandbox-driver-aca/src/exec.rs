//! Exec support for ACA sandboxes; git/search/services derive from this.
//!
//! ACA's `executeShellCommand` is one buffered, blocking REST call: no
//! stdin channel, no cancellation, no live streaming. [`AcaExec::run`] and
//! [`AcaExec::run_streaming`] both resolve to that single call — a caller
//! asking for stdin or a stop token gets [`Error::Unsupported`], and a
//! streaming caller gets its output replayed through the sink after the
//! call returns, honestly reporting `live_streaming: false`.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use sandbox_driver::{
    Capability, Error, Exec, ExecControls, ExecResult, ExecSpec, ExecStreamingResult, OutputStream,
    Result, Termination,
};

use crate::client::{AcaClient, aca_error};

/// Command execution against one ACA sandbox.
///
/// `env` is the sandbox's `spec.env` captured at create time (so
/// `GITHUB_TOKEN` and friends reach every exec, including derived git/
/// search/services calls that build their own [`ExecSpec`] without
/// re-supplying it); [`ExecSpec::launch_env`] is merged on top per call
/// (see [`merged_env`]) and wins on key collision.
pub struct AcaExec {
    pub client: Arc<AcaClient>,
    pub sandbox_id: String,
    pub workspace: String,
    pub env: BTreeMap<String, String>,
}

#[async_trait]
impl Exec for AcaExec {
    async fn run(&self, spec: &ExecSpec) -> Result<ExecResult> {
        self.run_streaming(spec, ExecControls::buffered())
            .await?
            .into_complete()
    }

    async fn run_streaming(
        &self,
        spec: &ExecSpec,
        controls: ExecControls,
    ) -> Result<ExecStreamingResult> {
        if spec.stdin.is_some() {
            return Err(Error::unsupported(Capability::ExecStdin));
        }
        if controls.stdin.is_some() {
            return Err(Error::unsupported(Capability::ExecStdinStream));
        }
        if controls.term.is_some() || controls.kill.is_some() {
            return Err(Error::unsupported(Capability::ExecStop));
        }

        let merged = merged_env(&self.env, spec);

        let cmd = build_command(
            &spec.program,
            &spec.args,
            spec.working_dir.as_deref(),
            &self.workspace,
            &merged,
        );

        let resp = self
            .client
            .exec(&self.sandbox_id, &cmd)
            .await
            .map_err(aca_error)?;

        let mut result = ExecResult::new(
            Termination::Exited,
            Some(resp.exit_code),
            Duration::from_millis(resp.execution_time_ms),
        );
        result.stdout = resp.stdout.into_bytes();
        result.stderr = resp.stderr.into_bytes();

        // ACA delivers output only after the call returns — there is
        // nothing to stream live. A caller with a sink still gets every
        // byte, replayed in order, before the buffered result comes back.
        if let Some(sink) = &controls.sink {
            if !result.stdout.is_empty() {
                sink(OutputStream::Stdout, result.stdout.clone()).await?;
            }
            if !result.stderr.is_empty() {
                sink(OutputStream::Stderr, result.stderr.clone()).await?;
            }
        }

        let mut streaming = ExecStreamingResult::new(result);
        streaming.streams_separated = true;
        Ok(streaming)
    }

    // `spawn_stdio` keeps the trait's default `Error::Unsupported` body:
    // ACA has no long-lived bidirectional stdio process API.
}

/// The env a call launches with: this exec's captured sandbox env,
/// overlaid with the spec's *launch* env — [`ExecSpec::launch_env`], not
/// `spec.env` directly. `launch_env()` re-blanks `BASH_ENV` for the Bash
/// helper spec (`ExecSpec::bash`) whatever the caller set, so a
/// caller-supplied `BASH_ENV` can never make the inner `bash -c` source an
/// arbitrary startup file ahead of the script; every other provider in
/// this crate (docker, daytona, host) merges through `launch_env()` for
/// the same reason. The spec's env wins on key collision.
fn merged_env(base: &BTreeMap<String, String>, spec: &ExecSpec) -> BTreeMap<String, String> {
    let mut merged = base.clone();
    merged.extend(spec.launch_env().into_owned());
    merged
}

/// Build the single command string ACA's `executeShellCommand` runs.
///
/// Pure — no I/O. `cwd` is `working_dir`, or `workspace` when unset. `env`
/// assignments (sorted — `env` is a `BTreeMap`) are prepended via
/// `env K=V...` so they reach the program without a shell `export`. Every
/// token is single-quoted with [`shq`], preserving `execvp` semantics
/// (`program`/`args` reach the process unchanged, no glob or word
/// splitting) even though ACA's transport is a single shell string.
fn build_command(
    program: &str,
    args: &[String],
    working_dir: Option<&str>,
    workspace: &str,
    env: &BTreeMap<String, String>,
) -> String {
    let cwd = working_dir.unwrap_or(workspace);
    let mut parts = vec![
        "cd".to_string(),
        shq(cwd),
        "&&".to_string(),
        "env".to_string(),
    ];
    for (key, value) in env {
        parts.push(shq(&format!("{key}={value}")));
    }
    parts.push(shq(program));
    parts.extend(args.iter().map(|arg| shq(arg)));
    parts.join(" ")
}

/// Single-quote a shell word, escaping embedded single quotes as `'\''`
/// (close the quote, an escaped literal `'`, reopen the quote).
///
/// `pub(crate)` so `fs.rs`'s exec-derived operations (`create_dir`/
/// `delete`/`rename`) share this instead of a duplicate escaper.
pub(crate) fn shq(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_cwd_to_workspace_when_unset() {
        let env = BTreeMap::new();
        let cmd = build_command(
            "git",
            &["rev-parse".into(), "HEAD".into()],
            None,
            "/workspace",
            &env,
        );
        assert!(cmd.starts_with("cd '/workspace' && "), "got: {cmd}");
        assert!(cmd.contains("git"));

        let cmd2 = build_command("ls", &[], Some("/tmp"), "/workspace", &env);
        assert!(cmd2.starts_with("cd '/tmp' && "), "got: {cmd2}");
    }

    #[test]
    fn injects_env_before_program() {
        let mut env = BTreeMap::new();
        env.insert("GITHUB_TOKEN".to_string(), "s3cr3t-not-real".to_string());
        let cmd = build_command("git", &["status".into()], None, "/workspace", &env);
        assert!(
            cmd.contains("env 'GITHUB_TOKEN=s3cr3t-not-real'"),
            "got: {cmd}"
        );
    }

    #[test]
    fn single_quotes_escape_embedded_quotes() {
        let env = BTreeMap::new();
        let cmd = build_command("echo", &["it's".into()], None, "/workspace", &env);
        assert!(cmd.contains(r"'it'\''s'"), "got: {cmd}");
    }

    #[test]
    fn env_keys_are_sorted_for_determinism() {
        let mut env = BTreeMap::new();
        env.insert("ZEBRA".to_string(), "1".to_string());
        env.insert("ALPHA".to_string(), "2".to_string());
        let cmd = build_command("true", &[], None, "/workspace", &env);
        let alpha = cmd.find("ALPHA").expect("alpha present");
        let zebra = cmd.find("ZEBRA").expect("zebra present");
        assert!(alpha < zebra, "got: {cmd}");
    }

    #[test]
    fn command_shape_is_cd_and_env_and_argv() {
        let mut env = BTreeMap::new();
        env.insert("FOO".to_string(), "bar".to_string());
        let cmd = build_command("echo", &["hi".into()], None, "/workspace", &env);
        assert_eq!(cmd, "cd '/workspace' && env 'FOO=bar' 'echo' 'hi'");
    }

    #[test]
    fn merged_env_overlays_spec_launch_env_over_base_env() {
        let mut base = BTreeMap::new();
        base.insert("GITHUB_TOKEN".to_string(), "base-token".to_string());
        base.insert("SHARED".to_string(), "base-value".to_string());
        let spec = ExecSpec::new("git").env_var("SHARED", "spec-value");

        let merged = merged_env(&base, &spec);

        assert_eq!(
            merged.get("GITHUB_TOKEN").map(String::as_str),
            Some("base-token"),
            "base env not carried over"
        );
        assert_eq!(
            merged.get("SHARED").map(String::as_str),
            Some("spec-value"),
            "spec env must win on collision"
        );
    }

    /// Mirrors the crate's own
    /// `the_bash_helpers_blank_bash_env_wins_at_launch` (sandbox-driver's
    /// `exec.rs`): a caller-supplied `BASH_ENV` on a Bash-helper spec must
    /// not reach the launched command, because `bash -c` sources it before
    /// running the script — merging through `spec.env` directly (instead
    /// of `spec.launch_env()`) would let a caller point `BASH_ENV` at an
    /// arbitrary startup file inside the sandbox.
    #[test]
    fn merged_env_blanks_bash_env_for_the_bash_helper_spec() {
        let base = BTreeMap::new();
        let spec = ExecSpec::bash("echo hi").env_var("BASH_ENV", "/etc/malicious-startup.sh");

        let merged = merged_env(&base, &spec);

        assert_eq!(
            merged.get("BASH_ENV").map(String::as_str),
            Some(""),
            "BASH_ENV must be re-blanked at launch, not the caller's override"
        );

        let cmd = build_command(&spec.program, &spec.args, None, "/workspace", &merged);
        assert!(
            cmd.contains("'BASH_ENV='") && !cmd.contains("malicious-startup"),
            "got: {cmd}"
        );
    }
}
