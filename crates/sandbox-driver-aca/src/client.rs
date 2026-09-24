//! Thin REST client for the Azure Container Apps sessions data-plane API.
//!
//! Ported from the `fabro-sandbox` ACA client
//! (`lib/components/fabro-sandbox/src/aca/client.rs`), trimmed to
//! create/get/delete/list. Exec/fs/lifecycle/egress land in a later task,
//! reusing [`AcaApiError`] defined here.

use std::sync::Arc;

use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};

use crate::auth::TokenSource;

/// `api-version` query parameter every data-plane request sends.
const API_VERSION: &str = "2026-02-01-preview";

// --- scope ------------------------------------------------------------

/// The subscription/resource-group/sandbox-group/region a client instance is
/// scoped to. Every data-plane URL is rooted at this scope's
/// [`AcaScope::collection_url`].
#[derive(Debug, Clone)]
pub struct AcaScope {
    pub subscription: String,
    pub resource_group: String,
    pub sandbox_group: String,
    /// Region-specific data-plane host, e.g. `"northeurope"` — distinct from
    /// the region-agnostic token audience
    /// ([`crate::auth::ACA_TOKEN_AUDIENCE`]).
    pub region: String,
}

impl AcaScope {
    /// `https://management.{region}.azuredevcompute.io/subscriptions/{sub}/resourceGroups/{rg}/sandboxGroups/{sg}/sandboxes`
    #[must_use]
    pub fn collection_url(&self) -> String {
        format!(
            "https://management.{}.azuredevcompute.io/subscriptions/{}/resourceGroups/{}/sandboxGroups/{}/sandboxes",
            self.region, self.subscription, self.resource_group, self.sandbox_group
        )
    }

    /// [`Self::collection_url`] plus `/{id}`.
    #[must_use]
    pub fn item_url(&self, id: &str) -> String {
        format!("{}/{id}", self.collection_url())
    }

    /// The `api-version` query parameter every data-plane request sends.
    #[must_use]
    pub fn api_version(&self) -> &'static str {
        API_VERSION
    }
}

// --- request/response shapes (ported from fabro-sandbox's capture doc) ----

/// `lifecycle.autoSuspendPolicy` — shared by the create request and every
/// sandbox response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AutoSuspendPolicy {
    pub enabled: bool,
    /// Seconds.
    pub interval: u64,
    /// Enum observed: `"Memory"`.
    pub mode: String,
}

/// `lifecycle` — shared by the create request and every sandbox response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Lifecycle {
    pub auto_suspend_policy: AutoSuspendPolicy,
}

/// `resources` as sent in the create request (no `disk` — that's assigned by
/// the server and only appears in responses, see [`SandboxResources`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateResources {
    /// Millicpu, e.g. `"1000m"`.
    pub cpu: String,
    /// e.g. `"2048Mi"`.
    pub memory: String,
}

/// `resources` as it appears in every sandbox response (adds `disk`).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxResources {
    pub cpu: String,
    pub memory: String,
    pub disk: String,
}

/// `sourcesRef.diskImage` as sent in the create request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateDiskImage {
    pub is_public: bool,
    pub name: String,
}

/// `sourcesRef` as sent in the create request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSourcesRef {
    pub disk_image: CreateDiskImage,
}

/// Body of `PUT .../sandboxes` (create).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSandboxRequest {
    pub lifecycle: Lifecycle,
    pub resources: CreateResources,
    pub sources_ref: CreateSourcesRef,
}

/// `sourcesRef.diskImage` as it appears in a sandbox response — the server
/// resolves the request's `name` to a concrete `id`, and always reports
/// `isPublic: false` for the resolved private copy.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiskImageRef {
    pub id: String,
    pub is_public: bool,
}

/// `sourcesRef` as it appears in a sandbox response.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourcesRef {
    pub disk_image: DiskImageRef,
}

/// `stateDetails`, present once a sandbox has been stopped at least once.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StateDetails {
    pub stopped_at: Option<String>,
    pub stopped_reason: Option<String>,
}

/// `state` field of a sandbox resource.
///
/// Named `AcaSandboxState` (not `SandboxState`) to avoid colliding with
/// `sandbox_driver::SandboxState`, which later tasks import alongside this
/// type. Only `"Running"`/`"Stopped"` were observed; `Unknown` is a
/// forward-compatible catch-all so an unrecognized state string fails soft
/// instead of breaking deserialization of the whole response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AcaSandboxState {
    Running,
    Stopped,
    #[serde(other)]
    Unknown,
}

/// The **Sandbox** resource — the common response shape for create/get/list.
///
/// Fields observed as always empty in this preview (`connections`,
/// `contentPackageDownloads`, `labels`, `ports`, `volumes`) are intentionally
/// unmodeled: `serde` ignores unrecognized response fields by default, so
/// they don't block deserialization, and nothing in create/get/list/delete
/// needs their contents.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxResource {
    pub id: String,
    pub state: AcaSandboxState,
    pub created_at: String,
    pub lifecycle: Lifecycle,
    pub resources: SandboxResources,
    pub sources_ref: SourcesRef,
    // Runtime/placement fields: present when Running, but a Stopped
    // sandbox's `get` response omits `region`/`managementUrl`/`vmmType`
    // entirely (only `state`/`resources`/`stateDetails`/`snapshotId`
    // remain).
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub management_url: Option<String>,
    #[serde(default)]
    pub vmm_type: Option<String>,
    /// Absent from the initial `create` response (server assigns egress IPs
    /// after the fact); present on `get`/`list`.
    #[serde(default)]
    pub outbound_ip_addresses: Vec<String>,
    /// Present once the sandbox has been stopped at least once.
    #[serde(default)]
    pub state_details: Option<StateDetails>,
    /// Sibling of `stateDetails` on the sandbox resource; present once the
    /// sandbox has been stopped/resumed.
    #[serde(default)]
    pub snapshot_id: Option<String>,
}

// --- error mapping ----------------------------------------------------

/// Typed classification of an ACA data-plane error response.
///
/// Reused by later exec/fs/lifecycle/egress endpoints on the same client, so
/// the status-code classification lives in one place.
#[derive(Debug, thiserror::Error)]
pub enum AcaApiError {
    /// HTTP 403 — names the role an operator needs to grant on the sandbox
    /// group for the caller's identity.
    #[error(
        "ACA data-plane request was denied (403) — the caller's identity is missing the \
         'Container Apps SandboxGroup Data Owner' role assignment on the sandbox group"
    )]
    Auth,

    /// HTTP 404 (captured live as `SandboxNotFound`).
    #[error("ACA sandbox not found")]
    NotFound,

    /// HTTP 409 (captured live as `GlobalSandboxNotRunning`).
    #[error("ACA sandbox is not running (GlobalSandboxNotRunning)")]
    NotRunning,

    /// Any other non-success status, or a transport/token failure (`status`
    /// `0`) that never reached the server.
    #[error("ACA data-plane request failed with HTTP {status}: {message}")]
    Other { status: u16, message: String },
}

/// Classify a non-success HTTP status into an [`AcaApiError`].
///
/// `body` is the raw response text; when it parses as the `problem+json`
/// shape, `title`/`detail` are folded into [`AcaApiError::Other`]'s message
/// for statuses that don't get a specific variant.
fn map_status(status: StatusCode, body: &str) -> AcaApiError {
    match status {
        StatusCode::FORBIDDEN => AcaApiError::Auth,
        StatusCode::NOT_FOUND => AcaApiError::NotFound,
        StatusCode::CONFLICT => AcaApiError::NotRunning,
        other => AcaApiError::Other {
            status: other.as_u16(),
            message: extract_problem_message(body).unwrap_or_else(|| body.to_string()),
        },
    }
}

/// Best-effort extraction of `title`/`detail` from a `problem+json` error
/// body.
fn extract_problem_message(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let title = value.get("title").and_then(serde_json::Value::as_str);
    let detail = value.get("detail").and_then(serde_json::Value::as_str);
    match (title, detail) {
        (Some(title), Some(detail)) => Some(format!("{title}: {detail}")),
        (Some(title), None) => Some(title.to_string()),
        (None, Some(detail)) => Some(detail.to_string()),
        (None, None) => None,
    }
}

// --- client -------------------------------------------------------------

/// Typed REST client over the ACA sandbox data plane.
///
/// One instance is scoped to a single subscription/resource-group/
/// sandbox-group/region quadruple ([`AcaScope`]) — every URL is rooted at
/// that scope. Callers are expected to build `http` with a sane
/// `User-Agent` (e.g.
/// `concat!("sandbox-driver-aca/", env!("CARGO_PKG_VERSION"))`) via
/// [`reqwest::Client::builder`]'s `.user_agent(...)`.
pub struct AcaClient {
    http: reqwest::Client,
    token: Arc<dyn TokenSource>,
    scope: AcaScope,
}

impl AcaClient {
    #[must_use]
    pub fn new(http: reqwest::Client, token: Arc<dyn TokenSource>, scope: AcaScope) -> Self {
        Self { http, token, scope }
    }

    /// `PUT .../sandboxes` — create a sandbox.
    pub async fn create_sandbox(
        &self,
        request: CreateSandboxRequest,
    ) -> Result<SandboxResource, AcaApiError> {
        let url = self.scope.collection_url();
        let response = self.send(Method::PUT, &url, Some(&request)).await?;
        let body = Self::ok_body(response, "create sandbox").await?;
        Self::decode(&body, "create sandbox")
    }

    /// `GET .../sandboxes/{id}` — returns `Ok(None)` on the captured
    /// `404 SandboxNotFound`.
    pub async fn get_sandbox(&self, id: &str) -> Result<Option<SandboxResource>, AcaApiError> {
        let url = self.scope.item_url(id);
        let response = self.send::<()>(Method::GET, &url, None).await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let body = Self::ok_body(response, "get sandbox").await?;
        Self::decode(&body, "get sandbox").map(Some)
    }

    /// `GET .../sandboxes` — bare JSON array, `[]` when empty.
    pub async fn list_sandboxes(&self) -> Result<Vec<SandboxResource>, AcaApiError> {
        let url = self.scope.collection_url();
        let response = self.send::<()>(Method::GET, &url, None).await?;
        let body = Self::ok_body(response, "list sandboxes").await?;
        Self::decode(&body, "list sandboxes")
    }

    /// `DELETE .../sandboxes/{id}`. Deletion is asynchronous server-side, so
    /// a successful call here only confirms the delete was accepted, not
    /// that the sandbox is gone yet.
    pub async fn delete_sandbox(&self, id: &str) -> Result<(), AcaApiError> {
        let url = self.scope.item_url(id);
        let response = self.send::<()>(Method::DELETE, &url, None).await?;
        Self::ok_body(response, "delete sandbox").await?;
        Ok(())
    }

    /// Build and send one authenticated JSON request (or no body, for
    /// `GET`/`DELETE`). Always sends `api-version` and `Authorization:
    /// Bearer <token>`.
    async fn send<B: Serialize + ?Sized>(
        &self,
        method: Method,
        url: &str,
        body: Option<&B>,
    ) -> Result<reqwest::Response, AcaApiError> {
        let token = self.token.token().await.map_err(|err| AcaApiError::Other {
            status: 0,
            message: format!("failed to acquire ACA bearer token: {err}"),
        })?;
        let mut builder = self
            .http
            .request(method, url)
            .query(&[("api-version", self.scope.api_version())])
            .bearer_auth(token);
        if let Some(body) = body {
            builder = builder.json(body);
        }
        builder.send().await.map_err(|err| AcaApiError::Other {
            status: 0,
            message: format!("ACA data-plane request failed: {err}"),
        })
    }

    /// Read the response body, mapping a non-success status to a classified
    /// [`AcaApiError`].
    async fn ok_body(response: reqwest::Response, op: &'static str) -> Result<String, AcaApiError> {
        let status = response.status();
        let body = response.text().await.map_err(|err| AcaApiError::Other {
            status: status.as_u16(),
            message: format!("failed to read ACA {op} response body: {err}"),
        })?;
        if status.is_success() {
            Ok(body)
        } else {
            Err(map_status(status, &body))
        }
    }

    fn decode<T: for<'de> Deserialize<'de>>(
        body: &str,
        op: &'static str,
    ) -> Result<T, AcaApiError> {
        serde_json::from_str(body).map_err(|err| AcaApiError::Other {
            status: 0,
            message: format!("failed to decode ACA {op} response: {err}"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collection_url_is_region_scoped() {
        let scope = AcaScope {
            subscription: "sub".into(),
            resource_group: "rg".into(),
            sandbox_group: "sg".into(),
            region: "northeurope".into(),
        };
        assert_eq!(
            scope.collection_url(),
            "https://management.northeurope.azuredevcompute.io/subscriptions/sub/resourceGroups/rg/sandboxGroups/sg/sandboxes"
        );
        assert_eq!(scope.api_version(), "2026-02-01-preview");
    }
}
