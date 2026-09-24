//! Azure AD authentication for the ACA data-plane client.
//!
//! [`TokenSource`] is the seam consumed by [`crate::client::AcaClient`] and
//! the provider's `connect()`. Production code goes through
//! [`EntraTokenSource`], which selects a credential chain via an explicit
//! auth-mode string (no env access of its own — the caller reads
//! `ACA_AUTH_MODE`, or whatever equivalent, and passes the mode in); tests
//! use [`FakeTokenSource`] so they never touch Entra.

use std::sync::Arc;

use anyhow::Context as _;
use azure_core::credentials::TokenCredential;
use azure_identity::{DeveloperToolsCredential, ManagedIdentityCredential};

/// Fixed audience for the ACA data-plane API.
pub const ACA_TOKEN_AUDIENCE: &str = "https://management.azuredevcompute.io";

/// Yields a bearer token for the ACA data-plane audience.
///
/// Production code goes through [`EntraTokenSource`]; tests use a fake so
/// they never touch Entra.
#[async_trait::async_trait]
pub trait TokenSource: Send + Sync {
    /// A bearer token string for the ACA data-plane audience.
    async fn token(&self) -> anyhow::Result<String>;
}

/// Production [`TokenSource`] backed by `azure_identity`, selecting between
/// two credential chains via an explicit auth-mode string passed to
/// [`EntraTokenSource::from_mode`]:
///
/// - `"managed"` (case-insensitive) — [`ManagedIdentityCredential`]
///   (system-assigned, via IMDS/App Service, no client id). Use this when
///   the process itself runs as an Azure-hosted workload and must
///   authenticate to the ACA data plane as that workload's identity.
/// - anything else — [`DeveloperToolsCredential`] (Azure CLI, then Azure
///   Developer CLI), for local `az login` development.
///
/// `azure_identity` 1.x removed `DefaultAzureCredential` in favor of these
/// audience-specific credential types (see the crate's CHANGELOG: "Replaced
/// `DefaultAzureCredential` with `DeveloperToolsCredential`").
pub struct EntraTokenSource {
    credential: Arc<dyn TokenCredential>,
    audience: String,
}

/// Which credential chain [`EntraTokenSource::from_mode`] should build.
/// Kept as a pure enum (rather than branching on the raw string inline) so
/// the selection logic is directly testable without touching process env or
/// constructing an Azure SDK credential.
#[derive(Debug, PartialEq)]
enum AuthMode {
    /// System-assigned managed identity (IMDS/App Service, no client id) —
    /// for when this process itself runs as an Azure-hosted workload.
    Managed,
    /// `DeveloperToolsCredential` (Azure CLI, then Azure Developer CLI) —
    /// for local `az login` development. The default for any value other
    /// than `"managed"` (case-insensitive), including unset/empty.
    Developer,
}

/// Pure mapping from a raw auth-mode string to an [`AuthMode`]. `None`
/// (unset) and any value other than a case-insensitive `"managed"` resolve
/// to [`AuthMode::Developer`].
fn auth_mode_from_env_value(value: Option<&str>) -> AuthMode {
    match value {
        Some(v) if v.eq_ignore_ascii_case("managed") => AuthMode::Managed,
        _ => AuthMode::Developer,
    }
}

impl EntraTokenSource {
    /// Builds a token source for the fixed [`ACA_TOKEN_AUDIENCE`], selecting
    /// the credential chain from the caller-supplied `mode` string (no env
    /// access here — the caller, e.g. the provider's `connect()`, reads
    /// `ACA_AUTH_MODE` and passes the value through).
    pub fn from_mode(mode: &str) -> anyhow::Result<Self> {
        let credential: Arc<dyn TokenCredential> = match auth_mode_from_env_value(Some(mode)) {
            AuthMode::Managed => ManagedIdentityCredential::new(None)
                .context("failed to build Entra managed-identity credential")?,
            AuthMode::Developer => DeveloperToolsCredential::new(None)
                .context("failed to build Entra developer-tools credential")?,
        };
        Ok(Self {
            credential,
            audience: ACA_TOKEN_AUDIENCE.to_string(),
        })
    }
}

#[async_trait::async_trait]
impl TokenSource for EntraTokenSource {
    async fn token(&self) -> anyhow::Result<String> {
        // Azure AD v2 (`get_token`) takes an OAuth *scope*, not a bare
        // resource. For a resource audience the scope is `<resource>/.default`
        // (all of the resource's statically-consented permissions). Passing the
        // bare resource makes the CLI credential append `openid profile
        // offline_access`, which AAD rejects with AADSTS70011. Append
        // `/.default` unless the caller already supplied it.
        let scope = if self.audience.ends_with("/.default") {
            self.audience.clone()
        } else {
            format!("{}/.default", self.audience.trim_end_matches('/'))
        };
        let access_token = self
            .credential
            .get_token(&[scope.as_str()], None)
            .await
            .context("failed to acquire Entra token for ACA audience")?;
        Ok(access_token.token.secret().to_string())
    }
}

/// Test-only [`TokenSource`] that returns a fixed token string.
pub struct FakeTokenSource(pub String);

#[async_trait::async_trait]
impl TokenSource for FakeTokenSource {
    async fn token(&self) -> anyhow::Result<String> {
        Ok(self.0.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_mode_maps_managed_case_insensitively_else_developer() {
        assert_eq!(auth_mode_from_env_value(Some("managed")), AuthMode::Managed);
        assert_eq!(auth_mode_from_env_value(Some("MANAGED")), AuthMode::Managed);
        assert_eq!(auth_mode_from_env_value(Some("dev")), AuthMode::Developer);
        assert_eq!(auth_mode_from_env_value(None), AuthMode::Developer);
    }

    #[tokio::test]
    async fn fake_token_source_returns_token() {
        let ts = FakeTokenSource("test-token".to_string());
        assert_eq!(ts.token().await.unwrap(), "test-token");
    }
}
