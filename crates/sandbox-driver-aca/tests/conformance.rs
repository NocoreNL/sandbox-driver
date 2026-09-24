//! The ACA provider against the black-box conformance suite, in process
//! and served over the plugin protocol.
//!
//! Each check provisions and deletes a real (billed) ACA sandbox, so
//! these tests require live Azure credentials (`ACA_SUBSCRIPTION_ID`,
//! `ACA_RESOURCE_GROUP`, `ACA_SANDBOX_GROUP`, `ACA_REGION`, and reachable
//! auth — VPN/IMDS for the managed identity, or `az login` for
//! `DeveloperToolsCredential`). [`AcaProvider::connect`] fails fast when
//! those are absent, and both tests skip (pass trivially) in that case so
//! non-Azure hosts stay green.

use std::sync::Arc;

use sandbox_driver::{SandboxProvider, SandboxSource, SandboxSpec};
use sandbox_driver_aca::provider::AcaProvider;
use sandbox_driver_conformance::{Conformance, SpecFactory};
use sandbox_driver_protocol::{PluginProvider, serve};
use tokio::io::{duplex, split};

/// The conformance image. The ACA plugin declares git/search/services/
/// one-shot unsupported (see `sandbox_driver_aca::aca_capabilities`), so
/// those checks are capability-gated and skip — no `with_git_clone_url`/
/// `with_one_shot_image` fixture is needed here, unlike docker's spec.
const TEST_IMAGE: &str = "ubuntu";

fn specs() -> SpecFactory {
    SpecFactory::new(|| {
        SandboxSpec::new(SandboxSource::Image {
            reference: TEST_IMAGE.to_owned(),
        })
        .working_directory("/workspace")
    })
}

#[tokio::test(flavor = "multi_thread")]
#[expect(
    clippy::print_stderr,
    reason = "the per-check report is the test's evidence"
)]
async fn aca_provider_passes_conformance() {
    let Ok(provider) = AcaProvider::connect().await else {
        // No ACA credentials in this environment; nothing to verify.
        eprintln!("skipping: ACA creds absent");
        return;
    };
    let report = Conformance::new(Arc::new(provider), specs()).run().await;
    eprintln!("{report}");
    report.assert_pass();
}

/// The same battery through the wire: what a host that links no provider
/// crate — Petri — actually exercises.
#[tokio::test(flavor = "multi_thread")]
#[expect(
    clippy::print_stderr,
    reason = "the per-check report is the test's evidence"
)]
async fn aca_provider_passes_conformance_over_the_wire() {
    let Ok(provider) = AcaProvider::connect().await else {
        eprintln!("skipping: ACA creds absent");
        return;
    };
    let (host_side, plugin_side) = duplex(1024 * 1024);
    let (host_read, host_write) = split(host_side);
    let (plugin_read, plugin_write) = split(plugin_side);
    tokio::spawn(serve(Arc::new(provider), plugin_read, plugin_write));
    let remote = PluginProvider::connect(host_read, host_write)
        .await
        .expect("handshake succeeds");
    assert_eq!(remote.kind().as_str(), "aca");
    let report = Conformance::new(Arc::new(remote), specs()).run().await;
    eprintln!("{report}");
    report.assert_pass();
}
