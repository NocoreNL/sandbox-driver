//! Serde-only config for the ACA sandbox driver: the typed shape of
//! `SandboxSpec.provider_config`. No Azure dependencies, so hosts can
//! build it without linking the driver.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AcaProviderConfig {
    /// ACA CPU request, e.g. "1000m". None → provider default.
    pub cpu: Option<String>,
    /// ACA memory request, e.g. "2048Mi". None → provider default.
    pub memory: Option<String>,
    /// Disk image name for the sandbox source. None → provider default.
    pub disk_image: Option<String>,
    /// Auto-suspend interval in seconds. None → provider default.
    pub auto_suspend_secs: Option<u64>,
    /// Per-run egress allow-domains, overriding the static ACA_EGRESS_ALLOW.
    pub egress_allow: Vec<String>,
}

impl AcaProviderConfig {
    /// Build the `serde_json::Value` a host puts in `SandboxSpec.provider_config`.
    pub fn into_value(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("AcaProviderConfig serializes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_value_and_rejects_unknown_fields() {
        let cfg = AcaProviderConfig {
            cpu: Some("2000m".into()),
            memory: Some("4096Mi".into()),
            disk_image: Some("ubuntu".into()),
            auto_suspend_secs: Some(600),
            egress_allow: vec!["*.github.com".into()],
        };
        let value = cfg.into_value();
        let back: AcaProviderConfig = serde_json::from_value(value).unwrap();
        assert_eq!(back.cpu.as_deref(), Some("2000m"));
        assert_eq!(back.egress_allow, vec!["*.github.com".to_string()]);

        let unknown = serde_json::json!({ "bogus": 1 });
        assert!(serde_json::from_value::<AcaProviderConfig>(unknown).is_err());
    }
}
