use serde::{Deserialize, Serialize};

use super::{
    ProcessingMode, Validate, require_strict_order, valid_lower_identity, validate_capabilities,
};
use crate::{
    Error, ErrorCode,
    identity::{CaptureId, Digest, ReproId},
};

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ComponentKind {
    Architecture,
    BoundaryAdapter,
    Core,
    Debugger,
    DependencyAdapter,
    Executor,
    OperatingSystem,
    Profile,
    Sdk,
    StateProvider,
    SubjectRuntime,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentIdentity {
    pub identity_digest: Digest,
    pub capabilities: Vec<String>,
    pub component_id: String,
    pub component_kind: ComponentKind,
    pub conformance_digest: Digest,
    pub protocol_max: u64,
    pub protocol_min: u64,
    pub version: String,
}

impl Validate for ComponentIdentity {
    fn validate(&self) -> Result<(), Error> {
        validate_capabilities(&self.capabilities)?;
        if self.component_id.is_empty()
            || !valid_lower_identity(self.component_id.as_bytes())
            || self.version.is_empty()
            || self.protocol_min == 0
            || self.protocol_min > self.protocol_max
        {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum SupportBundleFormat {
    #[serde(rename = "reproit.support-bundle.v1")]
    V1,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupportBundle {
    pub closure_policy_digest: Digest,
    pub components: Vec<ComponentIdentity>,
    pub format: SupportBundleFormat,
}

impl Validate for SupportBundle {
    fn validate(&self) -> Result<(), Error> {
        if self.components.is_empty() || self.components.len() > 64 {
            return Err(Error::schema_invalid());
        }
        let mut previous: Option<(ComponentKind, &str)> = None;
        for component in &self.components {
            component.validate()?;
            let current = (component.component_kind, component.component_id.as_str());
            if previous.is_some_and(|prior| prior >= current) {
                return Err(Error::schema_invalid());
            }
            previous = Some(current);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum SupportRegistryFormat {
    #[serde(rename = "reproit.support-registry.v1")]
    V1,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupportedProfile {
    pub capabilities: Vec<String>,
    pub implementation_digest: Digest,
    pub profile: String,
    pub profile_format: u64,
    pub support_bundle_digests: Vec<Digest>,
}

impl Validate for SupportedProfile {
    fn validate(&self) -> Result<(), Error> {
        validate_capabilities(&self.capabilities)?;
        if !valid_lower_identity(self.profile.as_bytes())
            || self.profile.len() > 128
            || !(1..=9_007_199_254_740_991).contains(&self.profile_format)
            || self.support_bundle_digests.is_empty()
            || self.support_bundle_digests.len() > 1_024
        {
            return Err(Error::schema_invalid());
        }
        require_strict_order(self.support_bundle_digests.iter().map(ToString::to_string))
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupportRegistry {
    pub bundle_digests: Vec<Digest>,
    pub format: SupportRegistryFormat,
    pub profiles: Vec<SupportedProfile>,
    pub release_version: String,
    pub signature: String,
    pub signer_key_id: String,
}

impl Validate for SupportRegistry {
    fn validate(&self) -> Result<(), Error> {
        if self.bundle_digests.is_empty()
            || self.bundle_digests.len() > 1_024
            || self.profiles.is_empty()
            || self.profiles.len() > 64
            || self.release_version.is_empty()
            || self.release_version.len() > 64
            || self.signer_key_id.is_empty()
            || self.signer_key_id.len() > 256
            || self.signature.len() != 86
        {
            return Err(Error::schema_invalid());
        }
        require_strict_order(self.bundle_digests.iter().map(ToString::to_string))?;
        let mut previous = None;
        for profile in &self.profiles {
            profile.validate()?;
            let identity = (profile.profile.as_str(), profile.profile_format);
            if previous.is_some_and(|prior| prior >= identity)
                || profile
                    .support_bundle_digests
                    .iter()
                    .any(|digest| self.bundle_digests.binary_search(digest).is_err())
            {
                return Err(Error::schema_invalid());
            }
            previous = Some(identity);
        }
        crate::crypto::decode_base64url::<64>(&self.signature)?;
        Ok(())
    }
}

impl SupportRegistry {
    #[must_use]
    pub fn authorizes_profile(&self, profile: &str, profile_format: u64) -> bool {
        self.profiles.iter().any(|registration| {
            registration.profile == profile && registration.profile_format == profile_format
        })
    }

    #[must_use]
    pub fn authorizes_bundle(
        &self,
        profile: &str,
        profile_format: u64,
        support_bundle_digest: Digest,
    ) -> bool {
        self.profiles.iter().any(|registration| {
            registration.profile == profile
                && registration.profile_format == profile_format
                && registration
                    .support_bundle_digests
                    .binary_search(&support_bundle_digest)
                    .is_ok()
        })
    }
}

pub fn verify_support_registry(
    registry: &SupportRegistry,
    expected_release_version: &str,
    expected_signer_key_id: &str,
    public_key: &[u8; 32],
) -> Result<(), Error> {
    let verified = (|| {
        registry.validate()?;
        if registry.release_version != expected_release_version
            || registry.signer_key_id != expected_signer_key_id
        {
            return Err(Error::schema_invalid());
        }
        let value = serde_json::to_value(registry).map_err(|_| Error::schema_invalid())?;
        crate::crypto::verify_signed_value(&value, public_key)
    })();
    verified.map_err(|_| {
        Error::new(
            ErrorCode::UnsupportedCapabilitySet,
            "The installed support-bundle registry is not authorized for this release.",
        )
    })
}

#[derive(Debug, Clone)]
pub struct VerifiedSupportRegistry {
    registry: SupportRegistry,
}

impl VerifiedSupportRegistry {
    pub fn new(
        registry: SupportRegistry,
        expected_release_version: &str,
        expected_signer_key_id: &str,
        public_key: &[u8; 32],
    ) -> Result<Self, Error> {
        verify_support_registry(
            &registry,
            expected_release_version,
            expected_signer_key_id,
            public_key,
        )?;
        Ok(Self { registry })
    }

    pub fn require_profile(&self, profile: &str, profile_format: u64) -> Result<(), Error> {
        if self.registry.authorizes_profile(profile, profile_format) {
            return Ok(());
        }
        Err(unsupported_profile())
    }

    pub fn require_bundle(
        &self,
        profile: &str,
        profile_format: u64,
        support_bundle_digest: Digest,
    ) -> Result<(), Error> {
        if self
            .registry
            .authorizes_bundle(profile, profile_format, support_bundle_digest)
        {
            return Ok(());
        }
        Err(unsupported_profile())
    }
}

fn unsupported_profile() -> Error {
    Error::new(
        ErrorCode::UnsupportedCapabilitySet,
        "The installed release does not authorize this profile or support bundle.",
    )
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeptReference {
    pub capsule_digest: Digest,
    pub capture_batch: String,
    pub capture_batch_digest: Digest,
    pub capture_id: CaptureId,
    pub format: u8,
    pub key_reference: String,
    pub profile: String,
    pub profile_format: u64,
    pub processing_mode: ProcessingMode,
    pub repro_id: ReproId,
}

impl Validate for KeptReference {
    fn validate(&self) -> Result<(), Error> {
        if self.format != 1
            || !valid_lower_identity(self.profile.as_bytes())
            || self.profile.len() > 128
            || !(1..=9_007_199_254_740_991).contains(&self.profile_format)
            || self.capture_batch.len() > 2_048
            || !valid_oci_digest_reference(&self.capture_batch)
            || self.key_reference.is_empty()
            || self.key_reference.len() > 2_048
        {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }
}

fn valid_oci_digest_reference(value: &str) -> bool {
    let Some((reference, digest)) = value.rsplit_once("@sha256:") else {
        return false;
    };
    let remote = reference.strip_prefix("oci://").is_some_and(|name| {
        !name.is_empty()
            && !name.contains('@')
            && !name.bytes().any(|byte| byte.is_ascii_whitespace())
    });
    let layout = reference
        .strip_prefix("oci-layout://")
        .map(|identity| identity.trim_end_matches('/'))
        .is_some_and(|identity| valid_lower_identity(identity.as_bytes()));
    (remote || layout)
        && digest.len() == 64
        && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        && !digest.bytes().any(|byte| byte.is_ascii_uppercase())
}
