//! ACA → sandbox-driver state mapping and [`SandboxStatus`] construction.
//!
//! Consumed by `describe()` (Task 11) and list/attach (Task 12): both need
//! to turn an ACA [`SandboxResource`] into the portable [`SandboxStatus`]
//! shape the rest of `sandbox-driver` understands.

use std::time::SystemTime;

use sandbox_driver::{SandboxId, SandboxState, SandboxStatus};

use crate::client::{AcaSandboxState, SandboxResource};
use crate::create::MANAGED_LABEL;

/// Map ACA's reported sandbox state to the portable [`SandboxState`].
///
/// ACA's data-plane only ever reports `Running`/`Stopped`, plus an
/// `Unknown` catch-all that [`AcaSandboxState`]'s `#[serde(other)]` folds
/// any other state string into — there is no ACA-reported
/// `Creating`/`Error`/etc. state to map to the richer [`SandboxState`]
/// variants. A sandbox that is still provisioning, or one that failed to
/// provision, therefore both surface as `Unknown` here; a caller that needs
/// to tell "still creating" apart from "failed" must poll `get_sandbox`
/// until the state settles to `Running` or a timeout elapses (Task 12's
/// create path), rather than rely on a distinct state this mapping cannot
/// produce.
#[must_use]
pub fn map_state(state: &AcaSandboxState) -> SandboxState {
    match state {
        AcaSandboxState::Running => SandboxState::Running,
        AcaSandboxState::Stopped => SandboxState::Stopped,
        AcaSandboxState::Unknown => SandboxState::Unknown,
    }
}

/// Build a [`SandboxStatus`] from an ACA [`SandboxResource`], as returned by
/// `create`/`get`/`list`.
///
/// `labels` is deliberately left at its default (empty): the ACA
/// list/attach response carries no labels (see [`SandboxResource`]'s doc
/// comment — `labels` is always empty in this preview), so the
/// caller-visible labels on a live handle are populated by `describe()`
/// (Task 11) instead, not here.
///
/// # Panics
///
/// Panics if `r.id` is not a valid [`SandboxId`] (empty, over 256 bytes, or
/// containing whitespace/control characters). ACA-issued sandbox ids are
/// never any of those, so this is treated the same as elsewhere in this
/// workspace (see e.g. `sandbox-driver-docker`'s `DockerSandbox`
/// construction): an invariant, not a runtime error path.
#[must_use]
pub fn status_from_ref(r: &SandboxResource) -> SandboxStatus {
    let id = SandboxId::try_new(r.id.clone()).expect("ACA sandbox id is a valid sandbox id");
    let mut status = SandboxStatus::new(id, map_state(&r.state));
    status.provider_state = format!("{:?}", r.state);
    status.region.clone_from(&r.region);
    status.created_at = parse_created_at(&r.created_at);
    status
}

/// Parse an ACA `createdAt` RFC 3339 timestamp into a [`SystemTime`].
///
/// Returns `None` on any parse failure rather than failing status
/// construction over a display-only field — a malformed/unexpected
/// timestamp shouldn't block callers from seeing the rest of the status.
fn parse_created_at(raw: &str) -> Option<SystemTime> {
    humantime::parse_rfc3339_weak(raw).ok()
}

/// Whether `k` is internal bookkeeping this plugin stamps on every sandbox
/// it creates ([`MANAGED_LABEL`]), rather than a user-supplied label.
#[must_use]
pub fn is_internal_label(k: &str) -> bool {
    k == MANAGED_LABEL
}

#[cfg(test)]
mod tests {
    use sandbox_driver::SandboxState;

    use super::*;
    use crate::client::{AutoSuspendPolicy, DiskImageRef, Lifecycle, SandboxResources, SourcesRef};

    #[test]
    fn maps_aca_states() {
        assert_eq!(map_state(&AcaSandboxState::Running), SandboxState::Running);
        assert_eq!(map_state(&AcaSandboxState::Stopped), SandboxState::Stopped);
        assert_eq!(map_state(&AcaSandboxState::Unknown), SandboxState::Unknown);
    }

    #[test]
    fn managed_label_is_internal() {
        assert!(is_internal_label(MANAGED_LABEL));
        assert!(!is_internal_label("user-label"));
    }

    fn sandbox_resource() -> SandboxResource {
        SandboxResource {
            id: "sb-123".to_string(),
            state: AcaSandboxState::Running,
            created_at: "2026-01-02T03:04:05Z".to_string(),
            lifecycle: Lifecycle {
                auto_suspend_policy: AutoSuspendPolicy {
                    enabled: true,
                    interval: 600,
                    mode: "Memory".to_string(),
                },
            },
            resources: SandboxResources {
                cpu: "1000m".to_string(),
                memory: "2048Mi".to_string(),
                disk: "10Gi".to_string(),
            },
            sources_ref: SourcesRef {
                disk_image: DiskImageRef {
                    id: "img-1".to_string(),
                    is_public: false,
                },
            },
            region: Some("northeurope".to_string()),
            management_url: None,
            vmm_type: None,
            outbound_ip_addresses: Vec::new(),
            state_details: None,
            snapshot_id: None,
        }
    }

    #[test]
    fn status_from_ref_builds_expected_status() {
        let status = status_from_ref(&sandbox_resource());
        assert_eq!(status.id.as_str(), "sb-123");
        assert_eq!(status.state, SandboxState::Running);
        assert_eq!(status.provider_state, "Running");
        assert_eq!(status.region.as_deref(), Some("northeurope"));
        assert!(status.labels.is_empty());
        assert!(status.created_at.is_some());
    }

    #[test]
    fn status_from_ref_tolerates_unparseable_created_at() {
        let mut resource = sandbox_resource();
        resource.created_at = "not-a-timestamp".to_string();
        let status = status_from_ref(&resource);
        assert_eq!(status.created_at, None);
    }
}
