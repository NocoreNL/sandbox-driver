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
/// (`exec.streams_separated`), the filesystem facet is native rather than
/// exec-derived (`fs.native`), and network egress is a domain allow-list
/// (`network.domain_allow_list`). Everything else — stdin, stop, live
/// streaming, upload/download, search/git/services (v1 has no native
/// implementation and no exec-derived fallback wired in), pty, snapshots,
/// volumes, access — stays at the minimal default. Conformance checks
/// enforce this both ways: a capability claimed here but not implemented
/// fails conformance, and vice versa.
pub fn aca_capabilities() -> Capabilities {
    let mut caps = Capabilities::minimal(Isolation::Container);
    caps.exec.streams_separated = true;
    caps.fs.native = true;
    caps.network.domain_allow_list = true;
    caps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aca_capabilities_declares_only_the_implemented_flags() {
        let caps = aca_capabilities();

        assert!(caps.exec.streams_separated);
        assert!(caps.fs.native);
        assert!(caps.network.domain_allow_list);

        // Honesty spot-check: v1 has no native git implementation and no
        // exec-derived fallback wired in, so this must stay false rather
        // than inheriting `GitCaps::default()`'s wire-compatibility
        // default of `true`.
        assert!(!caps.git.supported);
        assert!(!caps.search.supported);
        assert!(!caps.services.supported);

        assert!(!caps.exec.stdin);
        assert!(!caps.exec.stop);
        assert!(!caps.exec.live_streaming);
        assert!(!caps.exec.stdio_process);
        assert!(!caps.exec.stdin_stream);
        assert!(!caps.exec.environment);
        assert!(!caps.fs.upload);
        assert!(!caps.fs.download);
        assert!(!caps.fs.permissions);
        assert!(!caps.network.allow_all);
        assert!(!caps.network.block_all);
        assert!(!caps.network.cidr_allow_list);
        assert!(caps.pty.is_none());
        assert!(caps.snapshots.is_none());
        assert!(caps.volumes.is_none());
    }
}
