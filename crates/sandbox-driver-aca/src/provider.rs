//! `SandboxProvider` implementation for Azure Container Apps.
//!
//! Assembles every other module in this crate into one live provider:
//! [`AcaProvider::connect`]/[`AcaProvider::connect_explicit`] build the
//! [`AcaClient`] (auth + HTTP), and the `impl SandboxProvider` below drives
//! it through [`crate::create::plan`]/[`crate::create::create_body`],
//! [`crate::inspect`], and [`AcaSandbox`].

use std::collections::BTreeMap;
use std::env;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use sandbox_driver::{
    Action, Capabilities, Error, EventContext, EventEmitter, EventSubject, HealthStatus,
    ProviderError, ProviderHealth, ProviderKind, ResourceKind, Result, Sandbox, SandboxFilter,
    SandboxId, SandboxProvider, SandboxSpec, SandboxState, SandboxStatus,
};
use tokio::time::{Instant, sleep};

use crate::auth::EntraTokenSource;
use crate::client::{AcaClient, AcaScope, aca_error};
use crate::create::{
    self, AcaAppPlan, AcaDefaults, DEFAULT_AUTO_SUSPEND_SECS, DEFAULT_CPU, DEFAULT_DISK_IMAGE,
    DEFAULT_MEMORY,
};
use crate::inspect;
use crate::sandbox::AcaSandbox;

/// How long [`AcaProvider::create`] waits for a freshly created sandbox to
/// reach [`SandboxState::Running`] before giving up.
///
/// ACA's data plane never reports an `Error` state for a sandbox that fails
/// to provision (see [`crate::inspect::map_state`]'s doc comment) — a
/// timeout is the only way this loop can end badly, so it is the sole
/// failure signal `create` has.
const CREATE_TIMEOUT: Duration = Duration::from_secs(120);

/// Poll interval while [`AcaProvider::create`] waits for a created sandbox
/// to reach `Running`.
const CREATE_POLL_INTERVAL: Duration = Duration::from_secs(3);

/// Working directory used by [`AcaProvider::attach`], which has no
/// [`SandboxSpec`] to read a caller-requested one from. Matches
/// [`crate::create::plan`]'s own default for an unset
/// `working_directory`.
const ATTACH_WORKING_DIRECTORY: &str = "/workspace";

/// Resolved provider configuration — either read from the environment by
/// [`AcaProvider::connect`], or supplied directly by an embedding
/// application through [`AcaProvider::connect_explicit`].
#[derive(Clone, Debug)]
pub struct AcaConfig {
    pub subscription: String,
    pub resource_group: String,
    pub sandbox_group: String,
    /// Region-specific data-plane host, e.g. `"northeurope"`.
    pub region: String,
    /// `"managed"` (case-insensitive) selects a system-assigned managed
    /// identity; anything else (including empty/unset) selects
    /// `DeveloperToolsCredential`. See [`EntraTokenSource::from_mode`].
    pub auth_mode: String,
    /// Static egress allow-list fallback, used when a [`SandboxSpec`]
    /// carries neither `provider_config.egress_allow` nor a
    /// `NetworkPolicy::DomainAllowList`. See [`crate::create::plan`].
    pub egress_allow: Vec<String>,
}

/// The ACA sandbox provider: a thin, stateless driver over one
/// subscription/resource-group/sandbox-group/region scope.
pub struct AcaProvider {
    kind: ProviderKind,
    caps: Capabilities,
    scope: AcaScope,
    client: Arc<AcaClient>,
    defaults: AcaDefaults,
}

/// Reads one required environment variable, naming it in the error when
/// unset so a misconfigured deployment fails with a clear, actionable
/// message rather than an opaque `NotPresent`.
fn required_env(name: &str) -> anyhow::Result<String> {
    env::var(name).map_err(|_| anyhow::anyhow!("missing required environment variable {name}"))
}

/// Splits a comma-separated env value into trimmed, non-empty domains.
fn split_egress_allow(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|domain| !domain.is_empty())
        .map(str::to_owned)
        .collect()
}

impl AcaProvider {
    /// Connects to the Azure Container Apps data plane, reading every
    /// setting from the process environment: `ACA_SUBSCRIPTION_ID`,
    /// `ACA_RESOURCE_GROUP`, `ACA_SANDBOX_GROUP`, and `ACA_REGION` are
    /// required (a missing one names itself in the returned error);
    /// `ACA_AUTH_MODE` defaults to empty (`DeveloperToolsCredential`); and
    /// `ACA_EGRESS_ALLOW` is an optional comma-separated list.
    ///
    /// # Errors
    ///
    /// Returns an error naming the missing environment variable, or any
    /// error [`Self::connect_explicit`] returns.
    #[expect(
        clippy::unused_async,
        reason = "async to match connect()'s conventional shape across every \
                  sandbox-driver provider (and its await at the sole call site \
                  in main.rs); connect_explicit does the real, synchronous work"
    )]
    pub async fn connect() -> anyhow::Result<Self> {
        let subscription = required_env("ACA_SUBSCRIPTION_ID")?;
        let resource_group = required_env("ACA_RESOURCE_GROUP")?;
        let sandbox_group = required_env("ACA_SANDBOX_GROUP")?;
        let region = required_env("ACA_REGION")?;
        let auth_mode = env::var("ACA_AUTH_MODE").unwrap_or_default();
        let egress_allow = env::var("ACA_EGRESS_ALLOW")
            .map(|raw| split_egress_allow(&raw))
            .unwrap_or_default();

        Self::connect_explicit(AcaConfig {
            subscription,
            resource_group,
            sandbox_group,
            region,
            auth_mode,
            egress_allow,
        })
    }

    /// Builds a provider from an already-resolved [`AcaConfig`], without
    /// consulting the process environment. An embedding application that
    /// resolves its own configuration (a vault, a per-request scope) calls
    /// this directly instead of [`Self::connect`].
    ///
    /// # Errors
    ///
    /// Returns an error when `cfg.auth_mode` fails to build an Entra
    /// credential, or when the HTTP client cannot be constructed.
    pub fn connect_explicit(cfg: AcaConfig) -> anyhow::Result<Self> {
        let token = EntraTokenSource::from_mode(&cfg.auth_mode)?;
        let http = reqwest::Client::builder()
            .user_agent(concat!("sandbox-driver-aca/", env!("CARGO_PKG_VERSION")))
            .build()?;
        let scope = AcaScope {
            subscription: cfg.subscription,
            resource_group: cfg.resource_group,
            sandbox_group: cfg.sandbox_group,
            region: cfg.region,
        };
        let client = Arc::new(AcaClient::new(http, Arc::new(token), scope.clone()));
        let defaults = AcaDefaults {
            cpu: DEFAULT_CPU.into(),
            memory: DEFAULT_MEMORY.into(),
            disk_image: DEFAULT_DISK_IMAGE.into(),
            auto_suspend_secs: DEFAULT_AUTO_SUSPEND_SECS,
            egress_allow: cfg.egress_allow,
        };
        Ok(Self {
            kind: ProviderKind::try_new("aca")?,
            caps: crate::aca_capabilities(),
            scope,
            client,
            defaults,
        })
    }

    /// Polls `id` until it reaches [`SandboxState::Running`] or
    /// [`CREATE_TIMEOUT`] elapses.
    ///
    /// Propagates every failure mode as-is — a transient API error during
    /// polling, and a timeout — without attempting cleanup itself.
    /// [`Self::create`] is the single place that decides what to do with a
    /// sandbox left behind by a failed create, covering *every* error this
    /// (and every other step after `create_sandbox`) can return, not just
    /// the timeout.
    async fn wait_for_running(&self, id: &str) -> Result<()> {
        let deadline = Instant::now() + CREATE_TIMEOUT;
        loop {
            let resource = self.client.get_sandbox(id).await.map_err(aca_error)?;
            let running = resource.is_some_and(|resource| {
                inspect::map_state(&resource.state) == SandboxState::Running
            });
            if running {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(Error::Provider(ProviderError::new(
                    self.kind.clone(),
                    format!("sandbox did not reach Running within {CREATE_TIMEOUT:?}"),
                )));
            }
            sleep(CREATE_POLL_INTERVAL).await;
        }
    }

    /// Everything after the sandbox exists: wait for it to reach `Running`,
    /// set its egress policy, and build the handle.
    ///
    /// A failure anywhere in here leaves a billed ACA sandbox behind, so
    /// [`Self::create`] wraps this one call in best-effort cleanup that
    /// covers every failure mode uniformly, mirroring
    /// `sandbox-driver-daytona`'s `create_inner`/`cleanup_failed_create`
    /// split.
    async fn finish_create(&self, id: &str, plan: AcaAppPlan) -> Result<Arc<dyn Sandbox>> {
        self.wait_for_running(id).await?;

        self.client
            .set_egress(id, &plan.egress)
            .await
            .map_err(aca_error)?;

        let sandbox_id =
            SandboxId::try_new(id).map_err(|error| Error::invalid_spec("id", error.to_string()))?;
        let sandbox = AcaSandbox::new(
            sandbox_id,
            plan.working_dir,
            self.caps.clone(),
            self.client.clone(),
            plan.labels,
            plan.env,
        );
        Ok(Arc::new(sandbox))
    }
}

#[async_trait]
impl SandboxProvider for AcaProvider {
    fn kind(&self) -> &ProviderKind {
        &self.kind
    }

    fn capabilities(&self) -> &Capabilities {
        &self.caps
    }

    async fn create(
        &self,
        spec: &SandboxSpec,
        events: Option<EventContext>,
    ) -> Result<Arc<dyn Sandbox>> {
        let emitter = EventEmitter::new(self.kind.clone(), events);
        emitter
            .run(
                EventSubject::pending_sandbox(spec.name.clone()),
                Action::Create,
                |reporter| async move {
                    let plan = create::plan(spec, &self.defaults)?;
                    let body = create::create_body(&plan);
                    let created = self.client.create_sandbox(body).await.map_err(aca_error)?;
                    let id = created.id;

                    // The terminal event must identify the sandbox ACA just
                    // created; an id ACA hands back that this crate cannot
                    // represent is itself a create failure, so it takes the
                    // same best-effort cleanup as every later step.
                    match SandboxId::try_new(&id) {
                        Ok(event_id) => {
                            reporter.set_subject(EventSubject::sandbox(Some(event_id)));
                        }
                        Err(error) => {
                            let _ = self.client.delete_sandbox(&id).await;
                            return Err(Error::invalid_spec("id", error.to_string()));
                        }
                    }

                    // Everything from here on works against a sandbox that
                    // already exists (and is already billed): any failure —
                    // a transient error while polling for Running, the
                    // timeout, or a failed `set_egress` on an
                    // already-Running sandbox — must best-effort delete it
                    // before propagating the original error, or the
                    // sandbox leaks forever.
                    match self.finish_create(&id, plan).await {
                        Ok(sandbox) => Ok(sandbox),
                        Err(error) => {
                            let _ = self.client.delete_sandbox(&id).await;
                            Err(error)
                        }
                    }
                },
            )
            .await
    }

    async fn attach(
        &self,
        id: &SandboxId,
        events: Option<EventContext>,
    ) -> Result<Arc<dyn Sandbox>> {
        let emitter = EventEmitter::new(self.kind.clone(), events);
        emitter
            .run(
                EventSubject::sandbox(Some(id.clone())),
                Action::Attach,
                |_reporter| async move {
                    let resource = self
                        .client
                        .get_sandbox(id.as_str())
                        .await
                        .map_err(aca_error)?;
                    if resource.is_none() {
                        return Err(Error::NotFound {
                            resource: ResourceKind::Sandbox,
                            id: id.as_str().to_owned(),
                        });
                    }
                    // ACA reports no labels of its own (see
                    // `SandboxResource`'s doc comment) and `attach` has no
                    // `SandboxSpec` to read a caller-requested working
                    // directory or env from, so both start empty/default
                    // here — a documented limitation of attaching without
                    // the original create-time spec.
                    let sandbox = AcaSandbox::new(
                        id.clone(),
                        ATTACH_WORKING_DIRECTORY.to_owned(),
                        self.caps.clone(),
                        self.client.clone(),
                        BTreeMap::new(),
                        BTreeMap::new(),
                    );
                    Ok(Arc::new(sandbox) as Arc<dyn Sandbox>)
                },
            )
            .await
    }

    async fn list(&self, _filter: &SandboxFilter) -> Result<Vec<SandboxStatus>> {
        // Every sandbox in the scoped sandbox group belongs to this
        // provider — ACA offers no label filter to narrow the list
        // further, so `_filter` cannot be honored beyond that.
        let resources = self.client.list_sandboxes().await.map_err(aca_error)?;
        resources.iter().map(inspect::status_from_ref).collect()
    }

    async fn delete(&self, id: &SandboxId, events: Option<EventContext>) -> Result<()> {
        let emitter = EventEmitter::new(self.kind.clone(), events);
        emitter
            .run(
                EventSubject::sandbox(Some(id.clone())),
                Action::Delete,
                |_reporter| async move {
                    // `delete_sandbox` already treats a 404 as success, so
                    // this is idempotent as the trait requires without
                    // needing the default attach-then-delete.
                    self.client
                        .delete_sandbox(id.as_str())
                        .await
                        .map_err(aca_error)
                },
            )
            .await
    }

    async fn health(&self) -> Result<ProviderHealth> {
        // No live probe in v1: reporting `Ok` with the scoped identity is
        // enough for the preflight/diagnostics use case this serves today.
        let mut health = ProviderHealth::new(HealthStatus::Ok);
        health.identity = Some(format!(
            "subscription:{}/resourceGroup:{}",
            self.scope.subscription, self.scope.resource_group
        ));
        Ok(health)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> AcaConfig {
        AcaConfig {
            subscription: "S".into(),
            resource_group: "RG".into(),
            sandbox_group: "SG".into(),
            region: "northeurope".into(),
            auth_mode: "managed".into(),
            egress_allow: vec![],
        }
    }

    #[tokio::test]
    async fn connect_explicit_builds_provider_with_health_identity() {
        let provider = AcaProvider::connect_explicit(test_config()).unwrap();
        assert_eq!(provider.kind().as_str(), "aca");

        let health = provider.health().await.unwrap();
        assert_eq!(health.status, HealthStatus::Ok);
        assert_eq!(
            health.identity.as_deref(),
            Some("subscription:S/resourceGroup:RG")
        );
    }

    #[test]
    fn connect_explicit_never_touches_the_environment() {
        // Every field comes from `cfg`; a deliberately non-"managed"
        // auth_mode must select DeveloperToolsCredential without erroring,
        // regardless of what ACA_* variables the test process happens to
        // carry.
        let provider = AcaProvider::connect_explicit(AcaConfig {
            auth_mode: "developer".into(),
            ..test_config()
        })
        .unwrap();
        assert_eq!(provider.kind().as_str(), "aca");
    }

    #[test]
    fn split_egress_allow_trims_and_drops_empties() {
        assert_eq!(
            split_egress_allow(" a.example.com ,, b.example.com,"),
            vec!["a.example.com".to_string(), "b.example.com".to_string()]
        );
        assert!(split_egress_allow("").is_empty());
    }
}
