//! ACA sandbox driver: an image-based container provider over the Azure
//! Container Apps data-plane REST API. Implements SandboxProvider +
//! Sandbox + Exec + Filesystem; git/search/services derive from Exec.
pub mod auth;
pub mod client;
pub mod config;
pub mod create;
pub mod exec;
pub mod fs;
pub mod inspect;
pub mod provider;
pub mod sandbox;

use sandbox_driver::{Capabilities, Isolation};

/// The ACA provider's capability upper bound.
///
/// Starts from [`Capabilities::minimal`] and enables only what
/// [`provider::AcaProvider`]/[`sandbox::AcaSandbox`] actually implement:
/// stdout/stderr arrive as genuinely separate streams
/// (`exec.streams_separated`), a stop token cancels a streaming exec
/// (`exec.stop` — best-effort: see `crate::exec::AcaExec::exec_once`'s doc
/// comment), the filesystem facet is native rather than exec-derived
/// (`fs.native`), network egress is a domain allow-list
/// (`network.domain_allow_list`), and the git facet is derived from exec —
/// the `ubuntu` disk image ships `git`, so clone/checkout/fetch/push/pull
/// run as shell-outs the crate wires from `Exec` (`git.supported`).
/// `exec.stop` is not optional: the plugin WIRE
/// (`sandbox-driver-protocol`) sets `term`/`kill` on every streaming exec
/// unconditionally, so a provider declaring `exec.stop = false` would
/// reject every streaming exec that reaches it over the wire. Everything
/// else — stdin, live streaming, upload/download, search/services (v1 has
/// no native implementation and no exec-derived fallback wired in), pty,
/// snapshots, volumes, access — stays at the minimal default. Conformance
/// checks enforce this both ways: a capability claimed here but not
/// implemented fails conformance, and vice versa.
pub fn aca_capabilities() -> Capabilities {
    let mut caps = Capabilities::minimal(Isolation::Container);
    caps.exec.streams_separated = true;
    caps.exec.stop = true;
    caps.fs.native = true;
    caps.network.domain_allow_list = true;
    // Git facet, derived from exec (the ubuntu disk image ships git — the live
    // smoke's exec-based clone confirmed it). Fabro's target-repo
    // clone/checkout/run-branch push and the Run-Files diff go through this
    // facet, so it must be declared for a `--target`/`--target-repo` run.
    caps.git.supported = true;
    caps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aca_capabilities_declares_only_the_implemented_flags() {
        let caps = aca_capabilities();

        assert!(caps.exec.streams_separated);
        assert!(caps.exec.stop);
        assert!(caps.fs.native);
        assert!(caps.network.domain_allow_list);

        // Git derives from exec (the `ubuntu` image ships `git`); the live
        // integration smoke drove a real clone/checkout/commit/push through
        // this facet, and conformance's git suite passes over it.
        assert!(caps.git.supported);

        // Honesty spot-check: v1 has no native search/services
        // implementation and no exec-derived fallback wired in, so these
        // must stay false rather than inheriting the wire-compatibility
        // default of `true`.
        assert!(!caps.search.supported);
        assert!(!caps.services.supported);

        // Structural check covering every remaining field at once —
        // `Capabilities::minimal` with exactly the flags above flipped —
        // so a future accidental flip anywhere else (lifecycle.*, access.*,
        // logs, network.outbound_proxy, exec.*, fs.*, ...) fails this test
        // instead of silently over-claiming a capability the provider
        // doesn't implement. Compared via JSON since `Capabilities` has no
        // `PartialEq`.
        let mut expected = Capabilities::minimal(Isolation::Container);
        expected.exec.streams_separated = true;
        expected.exec.stop = true;
        expected.fs.native = true;
        expected.network.domain_allow_list = true;
        expected.git.supported = true;
        assert_eq!(
            serde_json::to_value(&caps).expect("capabilities serialize"),
            serde_json::to_value(&expected).expect("capabilities serialize"),
        );
    }
}
