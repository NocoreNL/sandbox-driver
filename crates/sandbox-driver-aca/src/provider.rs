//! `SandboxProvider` implementation for Azure Container Apps. Stub — filled in by a later task.

use std::sync::Arc;

use async_trait::async_trait;
use sandbox_driver::{
    Capabilities, EventContext, ProviderKind, Result, Sandbox, SandboxFilter, SandboxId,
    SandboxProvider, SandboxSpec, SandboxStatus,
};

/// The ACA sandbox provider.
///
/// Temporary stub: only `connect` has a real signature, and its body is
/// `unimplemented!()`. Every `SandboxProvider` method below is likewise
/// `unimplemented!()` — present only so `Arc<AcaProvider>` coerces to
/// `Arc<dyn SandboxProvider>` and the workspace compiles. The real fields
/// and implementation land in Task 12.
pub struct AcaProvider;

impl AcaProvider {
    /// Connect to the Azure Container Apps data plane.
    ///
    /// TODO(Task 12): implement — this is a temporary stub so the
    /// workspace (and `sandbox-driver-aca`'s `main.rs`) compiles.
    pub async fn connect() -> anyhow::Result<Self> {
        unimplemented!()
    }
}

#[async_trait]
impl SandboxProvider for AcaProvider {
    // TODO(Task 12): replace every `unimplemented!()` body below with the
    // real ACA implementation.

    fn kind(&self) -> &ProviderKind {
        unimplemented!()
    }

    fn capabilities(&self) -> &Capabilities {
        unimplemented!()
    }

    async fn create(
        &self,
        _spec: &SandboxSpec,
        _events: Option<EventContext>,
    ) -> Result<Arc<dyn Sandbox>> {
        unimplemented!()
    }

    async fn attach(
        &self,
        _id: &SandboxId,
        _events: Option<EventContext>,
    ) -> Result<Arc<dyn Sandbox>> {
        unimplemented!()
    }

    async fn list(&self, _filter: &SandboxFilter) -> Result<Vec<SandboxStatus>> {
        unimplemented!()
    }
}
