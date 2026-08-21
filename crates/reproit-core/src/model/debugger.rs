use serde::{Deserialize, Serialize};

use super::{ProcessorArchitecture, Validate, require_strict_order};
use crate::{Error, identity::Digest};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum DebuggerContractFormat {
    #[serde(rename = "reproit.debugger-contract.v1")]
    V1,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DebuggerProtocol {
    ChromeDevtools,
    DebugAdapter,
    GdbRemoteSerial,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DebuggerReadinessRule {
    CdpWebsocketReady,
    DapInitialized,
    GdbServerListening,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebuggerSourceMapping {
    pub developer_root: String,
    pub replay_root: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebuggerContract {
    pub artifact_digest: Digest,
    pub artifact_name: String,
    pub debugger_id: String,
    pub format: DebuggerContractFormat,
    pub launch_arguments: Vec<String>,
    pub protocol: DebuggerProtocol,
    pub readiness_rule: DebuggerReadinessRule,
    pub source_mappings: Vec<DebuggerSourceMapping>,
    pub supported_architectures: Vec<ProcessorArchitecture>,
    pub version: String,
}

impl Validate for DebuggerContract {
    fn validate(&self) -> Result<(), Error> {
        if !matches!(
            self.debugger_id.as_str(),
            "debugpy" | "delve" | "gdbserver" | "netcoredbg" | "node-inspector"
        ) || self.artifact_name.is_empty()
            || self.artifact_name.len() > 256
            || self.version.is_empty()
            || self.version.len() > 64
            || self.launch_arguments.is_empty()
            || self.launch_arguments.len() > 32
            || self.launch_arguments.iter().any(|value| {
                value.is_empty()
                    || value.len() > 1_024
                    || value
                        .bytes()
                        .any(|byte| byte == 0 || byte == b'\n' || byte == b'\r')
            })
            || self.source_mappings.is_empty()
            || self.source_mappings.len() > 16
            || self.supported_architectures.is_empty()
            || self.supported_architectures.len() > 2
        {
            return Err(Error::schema_invalid());
        }
        require_debugger_protocol(
            self.debugger_id.as_str(),
            self.protocol,
            self.readiness_rule,
        )?;
        require_strict_order(
            self.supported_architectures
                .iter()
                .map(|architecture| format!("{architecture:?}")),
        )?;
        let mut prior = None;
        for mapping in &self.source_mappings {
            validate_root(&mapping.developer_root)?;
            validate_root(&mapping.replay_root)?;
            if prior.is_some_and(|value: &str| value >= mapping.replay_root.as_str()) {
                return Err(Error::schema_invalid());
            }
            prior = Some(mapping.replay_root.as_str());
        }
        Ok(())
    }
}

fn require_debugger_protocol(
    debugger_id: &str,
    protocol: DebuggerProtocol,
    readiness: DebuggerReadinessRule,
) -> Result<(), Error> {
    let matches = match debugger_id {
        "gdbserver" => {
            protocol == DebuggerProtocol::GdbRemoteSerial
                && readiness == DebuggerReadinessRule::GdbServerListening
        }
        "node-inspector" => {
            protocol == DebuggerProtocol::ChromeDevtools
                && readiness == DebuggerReadinessRule::CdpWebsocketReady
        }
        "debugpy" | "delve" | "netcoredbg" => {
            protocol == DebuggerProtocol::DebugAdapter
                && readiness == DebuggerReadinessRule::DapInitialized
        }
        _ => false,
    };
    matches.then_some(()).ok_or_else(Error::schema_invalid)
}

fn validate_root(value: &str) -> Result<(), Error> {
    if value.len() < 2
        || value.len() > 512
        || !value.starts_with('/')
        || value.ends_with('/')
        || value.split('/').any(|part| part == "." || part == "..")
        || value
            .bytes()
            .any(|byte| byte == 0 || byte == b'\n' || byte == b'\r')
    {
        return Err(Error::schema_invalid());
    }
    Ok(())
}
