//! Sandbox creation (session pool acquisition) for the ACA provider: maps a
//! `sandbox_driver::SandboxSpec` to the ACA-specific [`AcaAppPlan`], and that
//! plan into the ACA create request body ([`create_body`]). Pure mapping —
//! no I/O, no Azure calls; the provider (Task 12) is the one that calls
//! [`crate::client::AcaClient::create_sandbox`] with the body this produces.

use std::collections::BTreeMap;
use std::fmt;

use sandbox_driver::{Error, NetworkPolicy, SandboxSource, SandboxSpec};

use crate::client::{
    AutoSuspendPolicy, CreateDiskImage, CreateResources, CreateSandboxRequest, CreateSourcesRef,
    Lifecycle,
};
use crate::config;

/// Label stamped on every sandbox this plugin creates (in [`AcaAppPlan::labels`]),
/// so a reconciler can distinguish sandboxes it manages from ones created
/// out-of-band. Never sent to ACA — the create body has no labels field.
pub const MANAGED_LABEL: &str = "sh.sandbox-driver.aca.managed";

/// Default ACA CPU request (millicpu string) when neither `provider_config`
/// nor `spec.resources.cpu_cores` supplies one. Consumed by Task 12 to build
/// [`AcaDefaults`].
pub const DEFAULT_CPU: &str = "1000m";
/// Default ACA memory request when neither `provider_config` nor
/// `spec.resources.memory_mb` supplies one. Consumed by Task 12 to build
/// [`AcaDefaults`].
pub const DEFAULT_MEMORY: &str = "2048Mi";
/// Default disk image name when neither `provider_config.disk_image` nor
/// the spec's `Image` source supplies one. Consumed by Task 12 to build
/// [`AcaDefaults`].
pub const DEFAULT_DISK_IMAGE: &str = "ubuntu";
/// Default auto-suspend interval, in seconds, when `provider_config` doesn't
/// override it. Consumed by Task 12 to build [`AcaDefaults`].
pub const DEFAULT_AUTO_SUSPEND_SECS: u64 = 600;

/// Provider-env fallbacks: the static defaults a host resolves once at
/// startup (e.g. from `ACA_*` environment variables) and passes to every
/// [`plan`] call. Built by Task 12.
#[derive(Clone, Debug)]
pub struct AcaDefaults {
    pub cpu: String,
    pub memory: String,
    pub disk_image: String,
    pub auto_suspend_secs: u64,
    pub egress_allow: Vec<String>,
}

/// The pure mapping result of a [`SandboxSpec`] against [`AcaDefaults`] and
/// its `provider_config`: everything [`create_body`] needs, plus the bits
/// the ACA create body has no field for (`labels`, `env`) but that the
/// resulting sandbox handle still needs to carry (label-based ownership
/// checks, per-exec env injection).
#[derive(Clone)]
pub struct AcaAppPlan {
    pub image: String,
    pub is_public: bool,
    pub cpu: String,
    pub memory: String,
    pub auto_suspend_secs: u64,
    pub working_dir: String,
    pub labels: BTreeMap<String, String>,
    pub env: BTreeMap<String, String>,
    /// Raw (unqualified) egress domains. [`crate::client::qualify_egress`]
    /// is applied later, by `set_egress` — not here.
    pub egress: Vec<String>,
}

// `env` is the designated secret channel (`spec.env.clone()` — API tokens,
// etc.), so hand-write `Debug` rather than deriving it, mirroring
// `sandbox_driver::SandboxSpec`'s redacting `Debug` impl: only the keys are
// printed, never the values.
impl fmt::Debug for AcaAppPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AcaAppPlan")
            .field("image", &self.image)
            .field("is_public", &self.is_public)
            .field("cpu", &self.cpu)
            .field("memory", &self.memory)
            .field("auto_suspend_secs", &self.auto_suspend_secs)
            .field("working_dir", &self.working_dir)
            .field("labels", &self.labels)
            .field("env_keys", &self.env.keys().collect::<Vec<_>>())
            .field("egress", &self.egress)
            .finish()
    }
}

/// Map `spec` to an [`AcaAppPlan`]. Pure — no I/O. `defaults` supplies the
/// provider-env fallbacks used when neither `spec.provider_config` nor the
/// portable spec fields carry a value.
///
/// # Errors
///
/// Returns `Err` when `spec.validate()` fails, when `spec.provider_config`
/// doesn't parse as [`sandbox_driver_aca_config::AcaProviderConfig`], when
/// `spec.source` isn't `Image` (the only source the ACA provider supports in
/// v1), or when `spec.network` is a `CidrAllowList` (ACA egress is
/// domain-based), `AllowAll`, or `Block` (neither is expressible in ACA's
/// domain-allow-list egress model).
pub fn plan(spec: &SandboxSpec, defaults: &AcaDefaults) -> Result<AcaAppPlan, Error> {
    spec.validate()?;

    let provider_config = config::provider_config(&spec.provider_config)?;

    let reference = match &spec.source {
        SandboxSource::Image { reference } => reference,
        SandboxSource::Dockerfile { .. } => {
            return Err(Error::invalid_spec(
                "source",
                "Dockerfile is not supported by the ACA provider",
            ));
        }
        SandboxSource::Snapshot { .. } => {
            return Err(Error::invalid_spec(
                "source",
                "Snapshot is not supported by the ACA provider",
            ));
        }
        SandboxSource::HostDirectory => {
            return Err(Error::invalid_spec(
                "source",
                "HostDirectory is not supported by the ACA provider",
            ));
        }
        // `SandboxSource` is `#[non_exhaustive]`: a source kind added by a
        // newer protocol peer that this build doesn't recognize is rejected
        // the same way as the other unsupported v1 sources.
        _ => {
            return Err(Error::invalid_spec(
                "source",
                "this source kind is not supported by the ACA provider",
            ));
        }
    };
    // Disk-image-name precedence: provider_config.disk_image > Image.reference
    // (when non-empty) > defaults.disk_image. An empty `reference` must not
    // win the second tier — that would send `diskImage.name=""` to ACA.
    let image = provider_config
        .disk_image
        .clone()
        .or_else(|| (!reference.is_empty()).then(|| reference.clone()))
        .unwrap_or_else(|| defaults.disk_image.clone());

    let cpu = provider_config.cpu.clone().unwrap_or_else(|| {
        spec.resources.cpu_cores.map_or_else(
            || defaults.cpu.clone(),
            |cores| format!("{}m", u64::from(cores) * 1000),
        )
    });
    let memory = provider_config.memory.clone().unwrap_or_else(|| {
        spec.resources
            .memory_mb
            .map_or_else(|| defaults.memory.clone(), |mb| format!("{mb}Mi"))
    });
    let auto_suspend_secs = provider_config
        .auto_suspend_secs
        .unwrap_or(defaults.auto_suspend_secs);

    let working_dir = spec
        .working_directory
        .as_deref()
        .filter(|dir| !dir.is_empty())
        .map_or_else(|| "/workspace".to_string(), ToString::to_string);

    let mut labels = spec.labels.clone();
    labels.insert(MANAGED_LABEL.to_string(), "true".to_string());

    let env = spec.env.clone();

    // Validate `spec.network` first, unconditionally — an invalid network
    // policy must be rejected even when `provider_config.egress_allow` would
    // otherwise make it moot, so a spec doesn't silently pass validation
    // today and start failing once egress_allow is removed from
    // provider_config later.
    let network_domains = match &spec.network {
        NetworkPolicy::DomainAllowList { domains } => Some(domains.clone()),
        NetworkPolicy::CidrAllowList { .. } => {
            return Err(Error::invalid_spec(
                "network",
                "ACA egress is domain-based; CIDR allow-lists are not supported",
            ));
        }
        NetworkPolicy::AllowAll => {
            return Err(Error::invalid_spec(
                "network",
                "ACA provider does not support the AllowAll network policy; use \
                 DomainAllowList or ProviderDefault",
            ));
        }
        NetworkPolicy::Block => {
            return Err(Error::invalid_spec(
                "network",
                "ACA provider does not support the Block network policy",
            ));
        }
        // `NetworkPolicy` is `#[non_exhaustive]`: `ProviderDefault` and any
        // policy kind added by a newer protocol peer fall back to the
        // static default rather than being rejected.
        NetworkPolicy::ProviderDefault | _ => None,
    };

    // Egress precedence: per-run provider_config.egress_allow > the spec's
    // own DomainAllowList > the static provider-env default.
    let egress = if provider_config.egress_allow.is_empty() {
        network_domains.unwrap_or_else(|| defaults.egress_allow.clone())
    } else {
        provider_config.egress_allow.clone()
    };

    Ok(AcaAppPlan {
        image,
        is_public: true,
        cpu,
        memory,
        auto_suspend_secs,
        working_dir,
        labels,
        env,
        egress,
    })
}

/// Build the ACA `PUT .../sandboxes` create request body from `plan`.
///
/// Deliberately omits `env` and `labels` — the ACA create request has
/// neither field. `plan.env`/`plan.labels` are carried on the plan for the
/// caller (the sandbox handle and a future label-based reconciler) instead.
#[must_use]
pub fn create_body(plan: &AcaAppPlan) -> CreateSandboxRequest {
    CreateSandboxRequest {
        lifecycle: Lifecycle {
            auto_suspend_policy: AutoSuspendPolicy {
                enabled: true,
                interval: plan.auto_suspend_secs,
                mode: "Memory".to_string(),
            },
        },
        resources: CreateResources {
            cpu: plan.cpu.clone(),
            memory: plan.memory.clone(),
        },
        sources_ref: CreateSourcesRef {
            disk_image: CreateDiskImage {
                is_public: plan.is_public,
                name: plan.image.clone(),
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandbox_driver::{NetworkPolicy, SandboxSource, SandboxSpec};

    fn defaults() -> AcaDefaults {
        AcaDefaults {
            cpu: "1000m".into(),
            memory: "2048Mi".into(),
            disk_image: "ubuntu".into(),
            auto_suspend_secs: 600,
            egress_allow: vec!["*.github.com".into()],
        }
    }

    #[test]
    fn image_source_maps_and_defaults_workspace_cwd() {
        let spec = SandboxSpec::new(SandboxSource::Image {
            reference: "ubuntu".into(),
        });
        let p = plan(&spec, &defaults()).unwrap();
        assert_eq!(p.working_dir, "/workspace");
        assert_eq!(p.cpu, "1000m");
        assert_eq!(p.image, "ubuntu");
        assert_eq!(p.egress, vec!["*.github.com".to_string()]);
    }

    #[test]
    fn spec_domain_allow_list_overrides_static_egress() {
        let spec = SandboxSpec::new(SandboxSource::Image {
            reference: "ubuntu".into(),
        })
        .network(NetworkPolicy::DomainAllowList {
            domains: vec!["example.com".into()],
        });
        assert_eq!(
            plan(&spec, &defaults()).unwrap().egress,
            vec!["example.com".to_string()]
        );
    }

    #[test]
    fn cidr_allow_list_is_rejected() {
        let spec = SandboxSpec::new(SandboxSource::Image {
            reference: "ubuntu".into(),
        })
        .network(NetworkPolicy::CidrAllowList {
            cidrs: vec!["10.0.0.0/8".into()],
        });
        assert!(plan(&spec, &defaults()).is_err());
    }

    #[test]
    fn allow_all_network_policy_is_rejected() {
        let spec = SandboxSpec::new(SandboxSource::Image {
            reference: "ubuntu".into(),
        })
        .network(NetworkPolicy::AllowAll);
        assert!(plan(&spec, &defaults()).is_err());
    }

    #[test]
    fn block_network_policy_is_rejected() {
        let spec = SandboxSpec::new(SandboxSource::Image {
            reference: "ubuntu".into(),
        })
        .network(NetworkPolicy::Block);
        assert!(plan(&spec, &defaults()).is_err());
    }

    #[test]
    fn empty_reference_falls_back_to_default_disk_image() {
        let spec = SandboxSpec::new(SandboxSource::Image {
            reference: String::new(),
        });
        let p = plan(&spec, &defaults()).unwrap();
        assert_eq!(p.image, defaults().disk_image);
    }

    #[test]
    fn debug_redacts_env_values_but_keeps_keys() {
        let spec = SandboxSpec::new(SandboxSource::Image {
            reference: "ubuntu".into(),
        })
        .env_var("GITHUB_TOKEN", "s3cr3t-not-real");
        let p = plan(&spec, &defaults()).unwrap();
        let debug = format!("{p:?}");
        assert!(!debug.contains("s3cr3t-not-real"), "debug: {debug}");
        assert!(debug.contains("GITHUB_TOKEN"), "debug: {debug}");
    }

    #[test]
    fn managed_label_is_stamped() {
        let spec = SandboxSpec::new(SandboxSource::Image {
            reference: "ubuntu".into(),
        });
        assert!(
            plan(&spec, &defaults())
                .unwrap()
                .labels
                .contains_key(MANAGED_LABEL)
        );
    }

    #[test]
    fn resources_map_cores_and_mb_to_aca_strings() {
        // `Resources` is `#[non_exhaustive]`, so a full struct literal from
        // this (downstream) crate doesn't compile — mutate the fields on
        // the builder-produced default instead.
        let mut spec = SandboxSpec::new(SandboxSource::Image {
            reference: "ubuntu".into(),
        });
        spec.resources.cpu_cores = Some(2);
        spec.resources.memory_mb = Some(4096);
        let p = plan(&spec, &defaults()).unwrap();
        assert_eq!(p.cpu, "2000m");
        assert_eq!(p.memory, "4096Mi");
    }

    #[test]
    fn create_body_omits_env_and_labels() {
        let spec = SandboxSpec::new(SandboxSource::Image {
            reference: "ubuntu".into(),
        })
        .env_var("SECRET", "shh")
        .label("team", "peppol");
        let p = plan(&spec, &defaults()).unwrap();
        let body = create_body(&p);
        let value = serde_json::to_value(&body).unwrap();
        assert!(value.get("env").is_none());
        assert!(value.get("labels").is_none());
        assert_eq!(value["resources"]["cpu"], "1000m");
        assert_eq!(value["resources"]["memory"], "2048Mi");
        assert_eq!(value["sourcesRef"]["diskImage"]["name"], "ubuntu");
        assert_eq!(value["sourcesRef"]["diskImage"]["isPublic"], true);
        assert_eq!(value["lifecycle"]["autoSuspendPolicy"]["interval"], 600);
        assert_eq!(value["lifecycle"]["autoSuspendPolicy"]["mode"], "Memory");
    }
}
