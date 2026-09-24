//! The `Sandbox` implementation for a running ACA session.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use sandbox_driver::{
    Capabilities, Error, Exec, Filesystem, PlatformInfo, ResourceKind, Result, Sandbox, SandboxId,
    SandboxStatus,
};

use crate::client::{AcaClient, aca_error};
use crate::exec::AcaExec;
use crate::fs::AcaFs;
use crate::inspect;

/// A live handle to one ACA sandbox session.
///
/// Stateless beyond identity and the negotiated capability set, per
/// [`Sandbox`]'s contract — current state always comes from [`Self::describe`]
/// via a fresh `client.get_sandbox` call, never cached here. `exec`/`fs` are
/// built once at construction, wired to the same `client`/`id`/`workspace`
/// so every derived operation (git/search/services, which build on
/// [`Sandbox::exec`]) reaches the same ACA session.
pub struct AcaSandbox {
    id: SandboxId,
    workspace: String,
    caps: Capabilities,
    client: Arc<AcaClient>,
    exec: AcaExec,
    fs: AcaFs,
    /// Labels this handle was created/attached with. ACA's data plane
    /// reports no labels of its own (see
    /// `crate::client::SandboxResource`'s doc comment), so [`Self::describe`]
    /// round-trips these onto every returned [`SandboxStatus`] instead of
    /// trusting the provider response.
    labels: BTreeMap<String, String>,
}

impl AcaSandbox {
    /// Builds a live handle. `env` is the sandbox's captured `spec.env`,
    /// threaded into the `exec` facet so every exec call (including
    /// derived git/search/services) sees it without re-supplying it.
    #[must_use]
    pub fn new(
        id: SandboxId,
        workspace: String,
        caps: Capabilities,
        client: Arc<AcaClient>,
        labels: BTreeMap<String, String>,
        env: BTreeMap<String, String>,
    ) -> Self {
        let sandbox_id = id.as_str().to_owned();
        let exec = AcaExec {
            client: Arc::clone(&client),
            sandbox_id: sandbox_id.clone(),
            workspace: workspace.clone(),
            env,
        };
        let fs = AcaFs::new(Arc::clone(&client), sandbox_id, workspace.clone());
        Self {
            id,
            workspace,
            caps,
            client,
            exec,
            fs,
            labels,
        }
    }
}

#[async_trait]
impl Sandbox for AcaSandbox {
    fn id(&self) -> &SandboxId {
        &self.id
    }

    fn capabilities(&self) -> &Capabilities {
        &self.caps
    }

    async fn describe(&self) -> Result<SandboxStatus> {
        let resource = self
            .client
            .get_sandbox(self.id.as_str())
            .await
            .map_err(aca_error)?
            .ok_or_else(|| Error::NotFound {
                resource: ResourceKind::Sandbox,
                id: self.id.as_str().to_owned(),
            })?;
        let mut status = inspect::status_from_ref(&resource)?;
        // The ACA data plane reports no labels (see `SandboxResource`'s
        // doc comment) — round-trip the labels this handle was
        // created/attached with instead of leaving them empty.
        status.labels = self.labels.clone();
        Ok(status)
    }

    fn working_directory(&self) -> &str {
        &self.workspace
    }

    async fn platform_info(&self) -> Result<PlatformInfo> {
        // The ACA disk image this plugin provisions is amd64 Linux; no
        // per-sandbox query exists for this, so it's a fixed fact rather
        // than a live lookup.
        Ok(PlatformInfo::new("linux", "x86_64", ""))
    }

    async fn start(&self) -> Result<()> {
        // `resume` on an already-running sandbox is success — idempotent,
        // matching the trait's "no-op when already running" contract.
        self.client
            .resume(self.id.as_str())
            .await
            .map_err(aca_error)
    }

    async fn stop(&self) -> Result<()> {
        self.client
            .suspend(self.id.as_str())
            .await
            .map_err(aca_error)
    }

    async fn delete(&self) -> Result<()> {
        // `delete_sandbox` treats a 404 (already gone, or never existed)
        // as success, so deleting an unknown id is idempotent as the
        // trait requires.
        self.client
            .delete_sandbox(self.id.as_str())
            .await
            .map_err(aca_error)
    }

    fn exec(&self) -> &dyn Exec {
        &self.exec
    }

    fn fs(&self) -> &dyn Filesystem {
        &self.fs
    }
}

#[cfg(test)]
mod tests {
    use sandbox_driver::Isolation;

    use super::*;
    use crate::auth::{FakeTokenSource, TokenSource};
    use crate::client::AcaScope;

    fn test_client() -> Arc<AcaClient> {
        let http = reqwest::Client::new();
        let token: Arc<dyn TokenSource> = Arc::new(FakeTokenSource("fake-token".to_string()));
        let scope = AcaScope {
            subscription: "sub".to_string(),
            resource_group: "rg".to_string(),
            sandbox_group: "sg".to_string(),
            region: "northeurope".to_string(),
        };
        Arc::new(AcaClient::new(http, token, scope))
    }

    #[test]
    fn constructor_wires_getters_as_expected() {
        let id = SandboxId::try_new("sb-123").expect("valid id");
        let caps = Capabilities::minimal(Isolation::Container);
        let mut labels = BTreeMap::new();
        labels.insert("owner".to_string(), "fabro".to_string());

        let sandbox = AcaSandbox::new(
            id.clone(),
            "/workspace".to_string(),
            caps,
            test_client(),
            labels,
            BTreeMap::new(),
        );

        assert_eq!(sandbox.id().as_str(), "sb-123");
        assert_eq!(sandbox.working_directory(), "/workspace");
        assert_eq!(sandbox.capabilities().isolation, Isolation::Container);
    }
}
