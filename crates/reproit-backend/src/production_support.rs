use std::path::PathBuf;

use reproit_core::{
    Error, ErrorCode,
    crypto::decode_base64url,
    model::{SupportRegistry, VerifiedSupportRegistry},
};
use serde::Deserialize;

use crate::support::{BackendSupportPackage, VerifiedBackendSupportCatalog};

const MAX_REGISTRY_BYTES: u64 = 1_048_576;
const MAX_BACKEND_CATALOG_BYTES: u64 = 4 * 1_024 * 1_024;
const REQUIRED_BACKEND_PACKAGE_COUNT: usize = 10;
const REQUIRED_SDK_CAPABILITIES: [&str; 5] =
    ["sdk.dotnet", "sdk.go", "sdk.node", "sdk.python", "sdk.rust"];
const REQUIRED_ARCHITECTURE_CAPABILITIES: [&str; 2] = ["architecture.arm64", "architecture.x86-64"];

pub struct ProductionSupportCatalog {
    pub backend: VerifiedBackendSupportCatalog,
    pub profiles: VerifiedSupportRegistry,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BackendSupportCatalogDocument {
    format: String,
    packages: Vec<BackendSupportPackage>,
}

pub fn load_support_catalog() -> Result<ProductionSupportCatalog, Error> {
    let registry_path = PathBuf::from(required("REPROIT_SUPPORT_REGISTRY_FILE")?);
    let packages_path = PathBuf::from(required("REPROIT_BACKEND_SUPPORT_PACKAGES_FILE")?);
    let key = decode_base64url::<32>(&required("REPROIT_RELEASE_VERIFICATION_KEY")?)?;
    load_support_catalog_from(
        &registry_path,
        &packages_path,
        &required("REPROIT_RELEASE_SIGNER_KEY_ID")?,
        &key,
    )
}

pub fn load_support_catalog_from(
    registry_path: &std::path::Path,
    packages_path: &std::path::Path,
    signer_key_id: &str,
    verification_key: &[u8; 32],
) -> Result<ProductionSupportCatalog, Error> {
    let registry_bytes = read_regular_path(registry_path, MAX_REGISTRY_BYTES)?;
    let registry: SupportRegistry = reproit_core::canonical::parse_strict(&registry_bytes)?;
    let profiles = VerifiedSupportRegistry::new(
        registry,
        env!("CARGO_PKG_VERSION"),
        signer_key_id,
        verification_key,
    )?;
    let catalog_bytes = read_regular_path(packages_path, MAX_BACKEND_CATALOG_BYTES)?;
    let document: BackendSupportCatalogDocument =
        reproit_core::canonical::parse_strict(&catalog_bytes).map_err(|_| invalid())?;
    if document.format != "reproit.backend-support-catalog.v1" {
        return Err(invalid());
    }
    let package_count = document.packages.len();
    let backend =
        VerifiedBackendSupportCatalog::new(document.packages, &profiles).map_err(|_| invalid())?;
    require_backend_v1_matrix(package_count, |sdk, architecture| {
        backend.select(sdk, architecture).map(|_| ())
    })?;
    Ok(ProductionSupportCatalog { backend, profiles })
}

fn require_backend_v1_matrix(
    package_count: usize,
    mut require_pair: impl FnMut(&str, &str) -> Result<(), Error>,
) -> Result<(), Error> {
    if package_count != REQUIRED_BACKEND_PACKAGE_COUNT {
        return Err(invalid());
    }
    for sdk in REQUIRED_SDK_CAPABILITIES {
        for architecture in REQUIRED_ARCHITECTURE_CAPABILITIES {
            require_pair(sdk, architecture).map_err(|_| invalid())?;
        }
    }
    Ok(())
}

fn read_regular_path(path: &std::path::Path, maximum_bytes: u64) -> Result<Vec<u8>, Error> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| invalid())?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > maximum_bytes {
        return Err(invalid());
    }
    std::fs::read(path).map_err(|_| invalid())
}

fn required(name: &str) -> Result<String, Error> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty() && value.len() <= 4_096)
        .ok_or_else(invalid)
}

fn invalid() -> Error {
    Error::new(
        ErrorCode::ConfigConflict,
        "The signed support package configuration is invalid.",
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn production_matrix_requires_every_backend_v1_pair() {
        let mut selected = BTreeSet::new();
        require_backend_v1_matrix(REQUIRED_BACKEND_PACKAGE_COUNT, |sdk, architecture| {
            assert!(selected.insert((sdk.to_owned(), architecture.to_owned())));
            Ok(())
        })
        .expect("the exact Backend v1 matrix should pass");

        assert_eq!(selected.len(), REQUIRED_BACKEND_PACKAGE_COUNT);
        for sdk in REQUIRED_SDK_CAPABILITIES {
            for architecture in REQUIRED_ARCHITECTURE_CAPABILITIES {
                assert!(selected.contains(&(sdk.to_owned(), architecture.to_owned())));
            }
        }
    }

    #[test]
    fn production_matrix_rejects_partial_and_oversized_catalogs() {
        for package_count in [
            REQUIRED_BACKEND_PACKAGE_COUNT - 1,
            REQUIRED_BACKEND_PACKAGE_COUNT + 1,
        ] {
            let error = require_backend_v1_matrix(package_count, |_, _| Ok(()))
                .expect_err("an inexact Backend v1 catalog size must fail closed");
            assert_eq!(error.code, ErrorCode::ConfigConflict);
        }
    }

    #[test]
    fn production_matrix_rejects_a_missing_required_pair() {
        let error =
            require_backend_v1_matrix(REQUIRED_BACKEND_PACKAGE_COUNT, |sdk, architecture| {
                if sdk == "sdk.node" && architecture == "architecture.arm64" {
                    return Err(Error::new(
                        ErrorCode::UnsupportedCapabilitySet,
                        "The required support bundle is absent.",
                    ));
                }
                Ok(())
            })
            .expect_err("a missing Backend v1 SDK and architecture pair must fail closed");

        assert_eq!(error.code, ErrorCode::ConfigConflict);
    }
}
