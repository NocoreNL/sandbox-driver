//! Driver-side config plumbing built on `sandbox-driver-aca-config`.

use sandbox_driver::Error;
use sandbox_driver_aca_config::AcaProviderConfig;
use serde::Deserialize;

pub fn provider_config(value: &serde_json::Value) -> Result<AcaProviderConfig, Error> {
    match value {
        serde_json::Value::Null => Ok(AcaProviderConfig::default()),
        serde_json::Value::Object(_) => AcaProviderConfig::deserialize(value)
            .map_err(|e| Error::invalid_spec("provider_config", e.to_string())),
        _ => Err(Error::invalid_spec("provider_config", "must be an object")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_config_parses_object_and_rejects_non_object() {
        assert!(
            provider_config(&serde_json::Value::Null)
                .unwrap()
                .cpu
                .is_none()
        );
        let obj = serde_json::json!({ "cpu": "2000m" });
        assert_eq!(provider_config(&obj).unwrap().cpu.as_deref(), Some("2000m"));
        assert!(provider_config(&serde_json::json!("nope")).is_err());
    }
}
