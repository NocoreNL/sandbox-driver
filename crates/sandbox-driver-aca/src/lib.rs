//! ACA sandbox driver: an image-based container provider over the Azure
//! Container Apps data-plane REST API. Implements SandboxProvider +
//! Sandbox + Exec + Filesystem; git/search/services derive from Exec.
pub mod auth;
pub mod client;
pub mod config;
pub mod create;
pub mod exec;
pub mod fs;
pub mod inspect;
pub mod provider;
pub mod sandbox;

use sandbox_driver::{Capabilities, Isolation};

pub fn aca_capabilities() -> Capabilities {
    Capabilities::minimal(Isolation::Container)
}
