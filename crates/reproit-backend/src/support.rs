use std::collections::BTreeMap;

use reproit_core::{
    Error, ErrorCode, canonical,
    identity::Digest,
    model::{
        ClosurePolicy, ComponentIdentity, ComponentKind, DebuggerContract, DebuggerProtocol,
        ProcessorArchitecture, SupportBundle, Validate, VerifiedSupportRegistry,
    },
};
use serde::{Deserialize, Serialize};

use crate::config::BackendSdk;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendSupportPackage {
    pub bundle: SupportBundle,
    pub closure_policy: ClosurePolicy,
    pub debugger: DebuggerContract,
}

impl BackendSupportPackage {
    pub fn digest(&self) -> Result<Digest, Error> {
        canonical::digest(&self.bundle)
    }
}

pub struct VerifiedBackendSupportCatalog {
    by_digest: BTreeMap<Digest, (String, String)>,
    packages: BTreeMap<(String, String), BackendSupportPackage>,
}

impl VerifiedBackendSupportCatalog {
    pub fn new(
        packages: Vec<BackendSupportPackage>,
        registry: &VerifiedSupportRegistry,
    ) -> Result<Self, Error> {
        if packages.is_empty() || packages.len() > 10 {
            return Err(unsupported_bundle());
        }
        let mut by_digest = BTreeMap::new();
        let mut verified = BTreeMap::new();
        for package in packages {
            validate_backend_support_package(&package)?;
            let digest = package.digest()?;
            registry.require_bundle("backend", 1, digest)?;
            let identity = package_identity(&package.bundle)?;
            if by_digest.insert(digest, identity.clone()).is_some()
                || verified.insert(identity, package).is_some()
            {
                return Err(unsupported_bundle());
            }
        }
        Ok(Self {
            by_digest,
            packages: verified,
        })
    }

    pub fn select(
        &self,
        sdk_capability: &str,
        architecture_capability: &str,
    ) -> Result<&BackendSupportPackage, Error> {
        self.packages
            .get(&(
                sdk_capability.to_owned(),
                architecture_capability.to_owned(),
            ))
            .ok_or_else(unsupported_bundle)
    }

    pub fn require_digest(&self, digest: Digest) -> Result<&BackendSupportPackage, Error> {
        let identity = self.by_digest.get(&digest).ok_or_else(unsupported_bundle)?;
        self.packages.get(identity).ok_or_else(unsupported_bundle)
    }
}

pub fn validate_backend_support_bundle(
    bundle: &SupportBundle,
    debugger: &DebuggerContract,
) -> Result<(), Error> {
    validate_backend_support_bundle_inner(bundle, debugger).map_err(|_| {
        Error::new(
            ErrorCode::UnsupportedCapabilitySet,
            "The support bundle does not contain its required standard debugger contract.",
        )
    })
}

pub fn build_backend_support_package(
    mut bundle: SupportBundle,
    closure_policy: ClosurePolicy,
    sdk: BackendSdk,
    architecture: ProcessorArchitecture,
    debugger: DebuggerContract,
    conformance_digest: Digest,
) -> Result<BackendSupportPackage, Error> {
    let (architecture_id, architecture_capability) = architecture_identity(architecture);
    bind_component(
        &mut bundle,
        ComponentKind::Architecture,
        architecture_id,
        architecture_capability,
        Digest::of(format!("reproit-architecture-{architecture_id}-1").as_bytes()),
        conformance_digest,
    )?;
    let (sdk_id, sdk_capability, boundary_id, runtime_id) = sdk_identity(sdk);
    bind_component(
        &mut bundle,
        ComponentKind::Sdk,
        sdk_id,
        sdk_capability,
        Digest::of(format!("reproit-sdk-{sdk_id}-1.0.0").as_bytes()),
        conformance_digest,
    )?;
    bind_mechanism_component(
        &mut bundle,
        ComponentKind::BoundaryAdapter,
        boundary_id,
        "operation.request-response",
        conformance_digest,
    )?;
    bind_mechanism_component(
        &mut bundle,
        ComponentKind::SubjectRuntime,
        runtime_id,
        &format!("runtime.{runtime_id}"),
        conformance_digest,
    )?;
    let protocol_capability = match debugger.protocol {
        DebuggerProtocol::ChromeDevtools => "debugger.chrome-devtools",
        DebuggerProtocol::DebugAdapter => "debugger.debug-adapter",
        DebuggerProtocol::GdbRemoteSerial => "debugger.gdb-remote",
    };
    bundle
        .components
        .retain(|component| component.component_kind != ComponentKind::Debugger);
    bundle.components.push(ComponentIdentity {
        capabilities: vec![protocol_capability.to_owned()],
        component_id: debugger.debugger_id.clone(),
        component_kind: ComponentKind::Debugger,
        conformance_digest,
        identity_digest: canonical::digest(&debugger)?,
        protocol_max: 1,
        protocol_min: 1,
        version: debugger.version.clone(),
    });
    bundle.components.sort_by(|left, right| {
        (left.component_kind, left.component_id.as_str())
            .cmp(&(right.component_kind, right.component_id.as_str()))
    });
    let package = BackendSupportPackage {
        bundle,
        closure_policy,
        debugger,
    };
    validate_backend_support_package(&package)?;
    Ok(package)
}

pub fn validate_backend_support_package(package: &BackendSupportPackage) -> Result<(), Error> {
    package.closure_policy.validate()?;
    if canonical::digest(&package.closure_policy)? != package.bundle.closure_policy_digest {
        return Err(unsupported_bundle());
    }
    validate_backend_support_bundle(&package.bundle, &package.debugger)
}

fn bind_mechanism_component(
    bundle: &mut SupportBundle,
    kind: ComponentKind,
    component_id: &str,
    capability: &str,
    conformance_digest: Digest,
) -> Result<(), Error> {
    let component = bundle
        .components
        .iter_mut()
        .find(|component| component.component_kind == kind)
        .ok_or_else(unsupported_bundle)?;
    component_id.clone_into(&mut component.component_id);
    component.capabilities = vec![capability.to_owned()];
    component.identity_digest =
        Digest::of(format!("reproit-{component_id}-{}", component.version).as_bytes());
    component.conformance_digest = conformance_digest;
    Ok(())
}

fn bind_component(
    bundle: &mut SupportBundle,
    kind: ComponentKind,
    component_id: &str,
    capability: &str,
    identity_digest: Digest,
    conformance_digest: Digest,
) -> Result<(), Error> {
    let component = bundle
        .components
        .iter_mut()
        .find(|component| component.component_kind == kind)
        .ok_or_else(unsupported_bundle)?;
    component_id.clone_into(&mut component.component_id);
    component.capabilities = vec![capability.to_owned()];
    component.identity_digest = identity_digest;
    component.conformance_digest = conformance_digest;
    Ok(())
}

const fn architecture_identity(
    architecture: ProcessorArchitecture,
) -> (&'static str, &'static str) {
    match architecture {
        ProcessorArchitecture::Arm64 => ("arm64", "architecture.arm64"),
        ProcessorArchitecture::X86_64 => ("x86-64", "architecture.x86-64"),
    }
}

const fn sdk_identity(sdk: BackendSdk) -> (&'static str, &'static str, &'static str, &'static str) {
    match sdk {
        BackendSdk::Dotnet => (
            "dotnet",
            "sdk.dotnet",
            "dotnet-request-response",
            "dotnet-native",
        ),
        BackendSdk::Go => ("go", "sdk.go", "go-request-response", "go-native"),
        BackendSdk::Nodejs => ("node", "sdk.node", "node-request-response", "node-native"),
        BackendSdk::Python => (
            "python",
            "sdk.python",
            "python-request-response",
            "python-native",
        ),
        BackendSdk::Rust => ("rust", "sdk.rust", "rust-request-response", "rust-native"),
    }
}

fn package_identity(bundle: &SupportBundle) -> Result<(String, String), Error> {
    let sdk = one_component_capability(bundle, ComponentKind::Sdk, "sdk.")?;
    let architecture =
        one_component_capability(bundle, ComponentKind::Architecture, "architecture.")?;
    if !matches!(
        sdk.as_str(),
        "sdk.dotnet" | "sdk.go" | "sdk.node" | "sdk.python" | "sdk.rust"
    ) || !matches!(
        architecture.as_str(),
        "architecture.arm64" | "architecture.x86-64"
    ) {
        return Err(unsupported_bundle());
    }
    Ok((sdk, architecture))
}

fn one_component_capability(
    bundle: &SupportBundle,
    kind: ComponentKind,
    prefix: &str,
) -> Result<String, Error> {
    let mut components = bundle
        .components
        .iter()
        .filter(|component| component.component_kind == kind);
    let component = components.next().ok_or_else(unsupported_bundle)?;
    if components.next().is_some() {
        return Err(unsupported_bundle());
    }
    component
        .capabilities
        .iter()
        .find(|capability| capability.starts_with(prefix))
        .cloned()
        .ok_or_else(unsupported_bundle)
}

fn unsupported_bundle() -> Error {
    Error::new(
        ErrorCode::UnsupportedCapabilitySet,
        "The installed Backend support package is not authorized for this release.",
    )
}

fn validate_backend_support_bundle_inner(
    bundle: &SupportBundle,
    debugger: &DebuggerContract,
) -> Result<(), Error> {
    bundle.validate()?;
    debugger.validate()?;
    let mut counts = BTreeMap::<ComponentKind, usize>::new();
    for component in &bundle.components {
        *counts.entry(component.component_kind).or_default() += 1;
    }
    for kind in [
        ComponentKind::Architecture,
        ComponentKind::BoundaryAdapter,
        ComponentKind::Core,
        ComponentKind::Debugger,
        ComponentKind::Executor,
        ComponentKind::OperatingSystem,
        ComponentKind::Profile,
        ComponentKind::Sdk,
        ComponentKind::SubjectRuntime,
    ] {
        if counts.get(&kind) != Some(&1) {
            return Err(Error::schema_invalid());
        }
    }
    if counts
        .get(&ComponentKind::DependencyAdapter)
        .copied()
        .unwrap_or(0)
        == 0
        || counts
            .get(&ComponentKind::StateProvider)
            .copied()
            .unwrap_or(0)
            == 0
    {
        return Err(Error::schema_invalid());
    }
    let debugger_component = bundle
        .components
        .iter()
        .find(|component| component.component_kind == ComponentKind::Debugger)
        .ok_or_else(Error::schema_invalid)?;
    let protocol_capability = match debugger.protocol {
        DebuggerProtocol::ChromeDevtools => "debugger.chrome-devtools",
        DebuggerProtocol::DebugAdapter => "debugger.debug-adapter",
        DebuggerProtocol::GdbRemoteSerial => "debugger.gdb-remote",
    };
    if debugger_component.component_id != debugger.debugger_id
        || debugger_component.version != debugger.version
        || debugger_component.identity_digest != canonical::digest(debugger)?
        || debugger_component.capabilities != [protocol_capability]
    {
        return Err(Error::schema_invalid());
    }
    let architecture = bundle
        .components
        .iter()
        .find(|component| component.component_kind == ComponentKind::Architecture)
        .ok_or_else(Error::schema_invalid)?;
    let required_architecture = match architecture.component_id.as_str() {
        "arm64" => ProcessorArchitecture::Arm64,
        "x86-64" => ProcessorArchitecture::X86_64,
        _ => return Err(Error::schema_invalid()),
    };
    if !debugger
        .supported_architectures
        .contains(&required_architecture)
    {
        return Err(Error::schema_invalid());
    }
    validate_runtime_debugger_binding(bundle, debugger)?;
    Ok(())
}

fn validate_runtime_debugger_binding(
    bundle: &SupportBundle,
    debugger: &DebuggerContract,
) -> Result<(), Error> {
    let sdk = one_component(bundle, ComponentKind::Sdk)?;
    let runtime = one_component(bundle, ComponentKind::SubjectRuntime)?;
    let expected = match sdk.component_id.as_str() {
        "dotnet" => ("dotnet-native", "netcoredbg"),
        "go" => ("go-native", "delve"),
        "node" => ("node-native", "node-inspector"),
        "python" => ("python-native", "debugpy"),
        "rust" => ("rust-native", "gdbserver"),
        _ => return Err(Error::schema_invalid()),
    };
    if runtime.component_id != expected.0 || debugger.debugger_id != expected.1 {
        return Err(Error::schema_invalid());
    }
    Ok(())
}

fn one_component(bundle: &SupportBundle, kind: ComponentKind) -> Result<&ComponentIdentity, Error> {
    let mut components = bundle
        .components
        .iter()
        .filter(|component| component.component_kind == kind);
    let component = components.next().ok_or_else(Error::schema_invalid)?;
    if components.next().is_some() {
        return Err(Error::schema_invalid());
    }
    Ok(component)
}

#[cfg(test)]
mod tests {
    use super::sdk_identity;
    use crate::config::BackendSdk;

    #[test]
    fn required_sdk_boundaries_are_framework_neutral() {
        let expected = [
            (BackendSdk::Dotnet, "dotnet-request-response"),
            (BackendSdk::Go, "go-request-response"),
            (BackendSdk::Nodejs, "node-request-response"),
            (BackendSdk::Python, "python-request-response"),
            (BackendSdk::Rust, "rust-request-response"),
        ];

        for (sdk, boundary_id) in expected {
            assert_eq!(sdk_identity(sdk).2, boundary_id);
        }
    }
}
