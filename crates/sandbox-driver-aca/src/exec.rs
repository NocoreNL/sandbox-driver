//! Exec support for ACA sandboxes; git/search/services derive from this.
//!
//! ACA's `executeShellCommand` is one buffered, blocking REST call: no
//! stdin channel, no live streaming. [`AcaExec::run`] and
//! [`AcaExec::run_streaming`] both resolve to that single call — a caller
//! asking for stdin gets [`Error::Unsupported`], and a streaming caller
//! gets its output replayed through the sink after the call returns,
//! honestly reporting `live_streaming: false`.
//!
//! Cancellation (`exec.stop`) is real, but best-effort on the server side:
//! [`AcaExec::exec_once`] races the ACA HTTP call against the caller's
//! `term`/`kill` tokens and the spec's timeout, and returns as soon as one
//! fires — but ACA has no API to abort a command already in flight, so a
//! cancelled command keeps running server-side (an orphan) until it exits
//! on its own or the sandbox auto-suspends. This is the plugin WIRE's own
//! requirement, not a choice: `sandbox-driver-protocol`'s streaming exec
//! path always sets `term`/`kill` on every call
//! (`sandbox-driver-protocol/src/server/exec.rs`), so a provider that
//! rejects their mere presence (as this crate used to) rejects every
//! streaming exec fabro sends.

use std::collections::BTreeMap;
use std::future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use sandbox_driver::{
    Capability, Error, Exec, ExecControls, ExecResult, ExecSpec, ExecStreamingResult,
    OutputCaptureBuffer, OutputStream, Result, Termination, run_with_stop_grace,
};
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;

use crate::client::{AcaClient, aca_error};
use crate::fs::abspath;

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

        run_with_stop_grace(spec, controls, |spec, controls| async move {
            self.exec_once(&spec, controls).await
        })
        .await
    }

    // `spawn_stdio` keeps the trait's default `Error::Unsupported` body:
    // ACA has no long-lived bidirectional stdio process API.
}

impl AcaExec {
    /// Runs one ACA exec call, racing it against the caller's `term`/`kill`
    /// tokens and the spec's own timeout (when [`run_with_stop_grace`]
    /// didn't already take the timeout over for its ladder).
    ///
    /// ACA cannot abort a command already in flight — whichever branch
    /// fires first decides the reported [`Termination`], but a cancelled
    /// command keeps running server-side until it exits on its own or the
    /// sandbox auto-suspends. `signal` stays `None` on every non-`Exited`
    /// branch: this crate has no way to observe what, if anything,
    /// actually stopped the remote process, and the conformance suite's
    /// stop checks skip the signal assertion when it's absent.
    async fn exec_once(
        &self,
        spec: &ExecSpec,
        controls: ExecControls,
    ) -> Result<ExecStreamingResult> {
        let merged = merged_env(&self.env, spec);

        let cmd = build_command(
            &spec.program,
            &spec.args,
            spec.working_dir.as_deref(),
            &self.workspace,
            &merged,
        );

        let started = Instant::now();
        let call = self.client.exec(&self.sandbox_id, &cmd);
        let term = cancelled(controls.term.as_ref());
        let kill = cancelled(controls.kill.as_ref());
        let timeout = sleep_or_never(spec.timeout);

        tokio::select! {
            res = call => {
                let resp = res.map_err(aca_error)?;

                // ACA hands back the whole buffer at once (no chunked
                // delivery), so sanitization runs over the complete buffer
                // in one pass — [`OutputSanitization::sanitize`], not the
                // chunk-at-a-time `OutputSanitizer` a live-streaming
                // provider needs. The sink and the retention cap both see
                // the *sanitized* bytes, matching every other provider in
                // this workspace (docker's `StreamOutput::drain` pushes a
                // chunk through the sanitizer before the sink or the
                // capture buffer ever see it).
                let stdout = spec.output_sanitization.sanitize(&resp.stdout.into_bytes());
                let stderr = spec.output_sanitization.sanitize(&resp.stderr.into_bytes());

                // ACA delivers output only after the call returns — there
                // is nothing to stream live. A caller with a sink still
                // gets every sanitized byte, replayed in order, before the
                // buffered (and possibly retention-capped) result comes
                // back.
                if let Some(sink) = &controls.sink {
                    if !stdout.is_empty() {
                        sink(OutputStream::Stdout, stdout.clone()).await?;
                    }
                    if !stderr.is_empty() {
                        sink(OutputStream::Stderr, stderr.clone()).await?;
                    }
                }

                let mut stdout_buffer = OutputCaptureBuffer::new(controls.retained_output_limit);
                stdout_buffer.push(&stdout);
                let (stdout, stdout_capture) = stdout_buffer.into_parts();

                let mut stderr_buffer = OutputCaptureBuffer::new(controls.retained_output_limit);
                stderr_buffer.push(&stderr);
                let (stderr, stderr_capture) = stderr_buffer.into_parts();

                let mut result = ExecResult::from_shell_status(
                    Termination::Exited,
                    Some(resp.exit_code),
                    Duration::from_millis(resp.execution_time_ms),
                );
                result.stdout = stdout;
                result.stderr = stderr;

                let mut streaming = ExecStreamingResult::new(result);
                streaming.streams_separated = true;
                streaming.stdout_capture = stdout_capture;
                streaming.stderr_capture = stderr_capture;
                Ok(streaming)
            }
            () = term => Ok(cancelled_result(Termination::Cancelled, started.elapsed())),
            () = kill => Ok(cancelled_result(Termination::Killed, started.elapsed())),
            () = timeout => Ok(cancelled_result(Termination::TimedOut, started.elapsed())),
        }
    }
}

/// Waits for `token` to cancel, or never resolves when there isn't one —
/// so it can sit as an always-present branch in a `tokio::select!`.
async fn cancelled(token: Option<&CancellationToken>) {
    match token {
        Some(token) => token.cancelled().await,
        None => future::pending().await,
    }
}

/// Waits for `timeout` to elapse, or never resolves when there isn't
/// one — mirrors [`cancelled`] for the spec's own deadline.
async fn sleep_or_never(timeout: Option<Duration>) {
    match timeout {
        Some(timeout) => sleep(timeout).await,
        None => future::pending().await,
    }
}

/// Builds the (empty-output) result for a call this crate ended early —
/// `term`/`kill`/`timeout` fired before the ACA call returned. `signal`
/// stays `None`: see [`AcaExec::exec_once`]'s doc comment.
fn cancelled_result(termination: Termination, elapsed: Duration) -> ExecStreamingResult {
    let result = ExecResult::new(termination, None, elapsed);
    let mut streaming = ExecStreamingResult::new(result);
    streaming.streams_separated = true;
    streaming
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
/// Pure — no I/O. `cwd` is `working_dir` resolved against `workspace` (see
/// [`crate::fs::abspath`] — a relative `working_dir` is joined onto
/// `workspace` instead of being handed to `cd` as-is, since ACA's shell
/// would otherwise resolve it against its own ambient cwd rather than the
/// sandbox's workspace), or `workspace` itself when unset. `cwd` is created
/// with `mkdir -p` before the `cd` — the ACA disk image's ubuntu root has
/// no `/workspace` (or any other cwd this plugin picks) preprovisioned, so
/// every exec would otherwise fail with `cd: can't cd to <dir>` before the
/// caller's command ever ran; `mkdir -p` is idempotent, so this is a no-op
/// once the directory exists. `env` assignments (sorted — `env` is a
/// `BTreeMap`) are prepended via `env K=V...` so they reach the program
/// without a shell `export`. Every token is single-quoted with [`shq`],
/// preserving `execvp` semantics (`program`/`args` reach the process
/// unchanged, no glob or word splitting) even though ACA's transport is a
/// single shell string.
fn build_command(
    program: &str,
    args: &[String],
    working_dir: Option<&str>,
    workspace: &str,
    env: &BTreeMap<String, String>,
) -> String {
    let cwd = working_dir.map_or_else(|| workspace.to_owned(), |dir| abspath(workspace, dir));
    let mut parts = vec![
        "mkdir".to_string(),
        "-p".to_string(),
        shq(&cwd),
        "&&".to_string(),
        "cd".to_string(),
        shq(&cwd),
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
        assert!(
            cmd.starts_with("mkdir -p '/workspace' && cd '/workspace' && "),
            "got: {cmd}"
        );
        assert!(cmd.contains("git"));

        let cmd2 = build_command("ls", &[], Some("/tmp"), "/workspace", &env);
        assert!(
            cmd2.starts_with("mkdir -p '/tmp' && cd '/tmp' && "),
            "got: {cmd2}"
        );
    }

    /// A relative `working_dir` must resolve against `workspace`, not
    /// against ACA's own ambient shell cwd — the conformance check
    /// `relative_working_dir_resolves` sets `working_dir("cwd-probe")` and
    /// expects `pwd` to report `<workspace>/cwd-probe`.
    #[test]
    fn relative_working_dir_resolves_against_workspace() {
        let env = BTreeMap::new();
        let cmd = build_command("pwd", &[], Some("cwd-probe"), "/workspace", &env);
        assert!(
            cmd.starts_with("mkdir -p '/workspace/cwd-probe' && cd '/workspace/cwd-probe' && "),
            "got: {cmd}"
        );

        // An absolute working_dir still passes through unchanged.
        let cmd2 = build_command("pwd", &[], Some("/tmp/abs"), "/workspace", &env);
        assert!(
            cmd2.starts_with("mkdir -p '/tmp/abs' && cd '/tmp/abs' && "),
            "got: {cmd2}"
        );
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
        assert_eq!(
            cmd,
            "mkdir -p '/workspace' && cd '/workspace' && env 'FOO=bar' 'echo' 'hi'"
        );
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

    /// `run_streaming` builds its result via
    /// [`ExecResult::from_shell_status`], not the plain constructor — ACA
    /// reports a foreign `SIGTERM` only as the shell's `128 + N` exit
    /// code, so decoding it is what lets `exec_reports_a_foreign_signal`
    /// (the conformance check) see `signal == Some(15)`. This pins the
    /// decode this crate now relies on: exercising the live path is the
    /// conformance suite's job, but the constant is worth freezing here.
    #[test]
    fn shell_status_143_decodes_to_sigterm() {
        let result =
            ExecResult::from_shell_status(Termination::Exited, Some(143), Duration::from_secs(0));
        assert_eq!(result.signal, Some(15), "128 + SIGTERM must decode to 15");
        assert_eq!(result.exit_code, Some(143), "the raw code stays intact");
    }
}
