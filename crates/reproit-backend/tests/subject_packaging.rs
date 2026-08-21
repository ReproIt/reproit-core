use std::{fs, path::Path};

use reproit_backend::subject::{
    SubjectPackagingLimits, SubjectPackagingRequest, freeze_running_subject,
};
use reproit_core::{
    ErrorCode,
    model::{DebugArtifactKind, SubjectRuntimeFamily, Validate},
};
use tempfile::TempDir;

#[test]
fn all_five_runtime_families_freeze_a_complete_subject() {
    for family in [
        SubjectRuntimeFamily::Rust,
        SubjectRuntimeFamily::Go,
        SubjectRuntimeFamily::Python,
        SubjectRuntimeFamily::Node,
        SubjectRuntimeFamily::Dotnet,
    ] {
        let fixture = Fixture::new(family);
        let staging = fixture.temporary.path().join("frozen");
        let frozen = freeze_running_subject(&fixture.request, &staging).unwrap();

        frozen.manifest.validate().unwrap();
        assert!(!frozen.objects.is_empty());
        assert!(frozen.objects.iter().all(|object| object.path.is_file()));
        assert_eq!(frozen.manifest.runtime_family, family);
        assert!(staging.is_dir());

        drop(frozen);
        assert!(
            !staging.exists(),
            "successful packaging must clean up on drop"
        );
    }
}

#[test]
fn language_debug_artifacts_bind_the_exact_module_digest() {
    for (family, expected_kind) in [
        (SubjectRuntimeFamily::Rust, DebugArtifactKind::Dwarf),
        (SubjectRuntimeFamily::Go, DebugArtifactKind::Dwarf),
        (
            SubjectRuntimeFamily::Python,
            DebugArtifactKind::InterpretedSourceIdentity,
        ),
        (
            SubjectRuntimeFamily::Node,
            DebugArtifactKind::InterpretedSourceIdentity,
        ),
        (SubjectRuntimeFamily::Dotnet, DebugArtifactKind::PortablePdb),
    ] {
        let fixture = Fixture::new(family);
        let frozen =
            freeze_running_subject(&fixture.request, &fixture.temporary.path().join("frozen"))
                .unwrap();
        let binding = frozen
            .manifest
            .debug_artifacts
            .iter()
            .find(|binding| binding.kind == expected_kind)
            .unwrap();
        assert!(
            frozen
                .manifest
                .modules
                .iter()
                .any(|module| module.module_digest == binding.module_digest)
        );
    }
}

#[test]
fn incomplete_and_unbounded_subjects_fail_before_staging_survives() {
    let fixture = Fixture::new(SubjectRuntimeFamily::Python);
    let link = fixture.temporary.path().join("app/unsafe-link");
    create_symlink(&fixture.request.entrypoint, &link);
    let staging = fixture.temporary.path().join("incomplete");
    let error = freeze_running_subject(&fixture.request, &staging).unwrap_err();
    assert_eq!(error.code, ErrorCode::IncompleteCandidate);
    assert!(!staging.exists());

    fs::remove_file(link).unwrap();
    let mut bounded = fixture.request.clone();
    bounded.limits.maximum_file_bytes = 1;
    let staging = fixture.temporary.path().join("unbounded");
    let error = freeze_running_subject(&bounded, &staging).unwrap_err();
    assert_eq!(error.code, ErrorCode::UploadLimitExceeded);
    assert!(!staging.exists());
}

#[test]
fn zero_byte_subject_files_freeze_with_exact_digest_and_size() {
    let fixture = Fixture::new(SubjectRuntimeFamily::Python);
    let empty = fixture.temporary.path().join("app/empty.py");
    fs::write(&empty, []).unwrap();
    let staging = fixture.temporary.path().join("frozen-empty");
    let frozen = freeze_running_subject(&fixture.request, &staging).unwrap();
    let empty_digest = reproit_core::identity::Digest::of(&[]);

    let object = frozen
        .manifest
        .objects
        .iter()
        .find(|object| object.digest == empty_digest)
        .expect("the empty file must have one subject object");
    assert_eq!(object.size, 0);
    assert!(
        frozen
            .manifest
            .files
            .iter()
            .any(|file| { file.path.ends_with("/empty.py") && file.object_digest == empty_digest })
    );
    assert!(frozen.objects.iter().any(|object| {
        object.digest == empty_digest && fs::read(&object.path).unwrap().is_empty()
    }));
}

struct Fixture {
    request: SubjectPackagingRequest,
    temporary: TempDir,
}

impl Fixture {
    fn new(family: SubjectRuntimeFamily) -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("app");
        fs::create_dir(&root).unwrap();
        let entrypoint = match family {
            SubjectRuntimeFamily::Rust | SubjectRuntimeFamily::Go => {
                let path = root.join("service");
                fs::write(&path, b"native application fixture").unwrap();
                fs::write(root.join("service.debug"), b"DWARF fixture").unwrap();
                path
            }
            SubjectRuntimeFamily::Python => {
                fs::write(root.join("app.py"), b"print('fixture')\n").unwrap();
                std::env::current_exe().unwrap()
            }
            SubjectRuntimeFamily::Node => {
                fs::write(root.join("app.js"), b"console.log('fixture')\n").unwrap();
                fs::write(root.join("app.js.map"), b"{}\n").unwrap();
                std::env::current_exe().unwrap()
            }
            SubjectRuntimeFamily::Dotnet => {
                let path = root.join("app.dll");
                fs::write(&path, b"managed application fixture").unwrap();
                fs::write(root.join("app.pdb"), b"portable PDB fixture").unwrap();
                fs::write(root.join("app.deps.json"), b"{}\n").unwrap();
                fs::write(root.join("app.runtimeconfig.json"), b"{}\n").unwrap();
                path
            }
        };
        Self {
            request: SubjectPackagingRequest {
                application_root: root,
                architecture: "architecture.x86-64".to_owned(),
                arguments: Vec::new(),
                entrypoint,
                environment_names: Vec::new(),
                limits: SubjectPackagingLimits {
                    maximum_file_bytes: 64 * 1024 * 1024,
                    maximum_files: 1_024,
                    maximum_total_bytes: 512 * 1024 * 1024,
                },
                operating_system: "operating-system.linux".to_owned(),
                runtime_family: family,
            },
            temporary,
        }
    }
}

#[cfg(unix)]
fn create_symlink(target: &Path, link: &Path) {
    std::os::unix::fs::symlink(target, link).unwrap();
}

#[cfg(windows)]
fn create_symlink(target: &Path, link: &Path) {
    std::os::windows::fs::symlink_file(target, link).unwrap();
}
