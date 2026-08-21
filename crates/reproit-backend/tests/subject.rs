use std::{fs, path::PathBuf};

use reproit_backend::subject::transfer_file_subject;
use reproit_core::{
    ErrorCode,
    identity::Digest,
    model::{Subject, SubjectFormat},
};

#[test]
fn exact_file_subject_transfers_to_a_new_read_only_target() {
    let root = temporary_root("complete");
    let source = root.join("source");
    let target = root.join("target");
    fs::write(&source, b"immutable subject").unwrap();
    let subject = subject(&source, Digest::of(b"immutable subject"));

    assert_eq!(
        transfer_file_subject(&subject, &target, 1024).unwrap(),
        b"immutable subject"
    );
    assert_eq!(fs::read(&target).unwrap(), b"immutable subject");
    assert!(fs::metadata(&target).unwrap().permissions().readonly());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn changed_missing_unsupported_and_oversize_sources_fail_without_a_target() {
    let root = temporary_root("negative");
    let source = root.join("source");
    fs::write(&source, b"immutable subject").unwrap();

    let changed = subject(&source, Digest::of(b"changed"));
    let target = root.join("changed-target");
    assert_eq!(
        transfer_file_subject(&changed, &target, 1024)
            .unwrap_err()
            .code,
        ErrorCode::SubjectDigestMismatch
    );
    assert!(!target.exists());

    let missing = subject(&root.join("missing"), Digest::of(b"missing"));
    assert_eq!(
        transfer_file_subject(&missing, &root.join("missing-target"), 1024)
            .unwrap_err()
            .code,
        ErrorCode::ArtifactNotFound
    );

    let mut unsupported = subject(&source, Digest::of(b"immutable subject"));
    unsupported.artifact_uri = "oci://customer.example/subject@sha256:00".to_owned();
    assert_eq!(
        transfer_file_subject(&unsupported, &root.join("unsupported-target"), 1024)
            .unwrap_err()
            .code,
        ErrorCode::Unsupported
    );

    let exact = subject(&source, Digest::of(b"immutable subject"));
    assert_eq!(
        transfer_file_subject(&exact, &root.join("large-target"), 4)
            .unwrap_err()
            .code,
        ErrorCode::ArtifactNotFound
    );
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn a_symlink_source_fails_closed() {
    use std::os::unix::fs::symlink;

    let root = temporary_root("symlink");
    let real = root.join("real");
    let link = root.join("link");
    fs::write(&real, b"immutable subject").unwrap();
    symlink(&real, &link).unwrap();
    let error = transfer_file_subject(
        &subject(&link, Digest::of(b"immutable subject")),
        &root.join("target"),
        1024,
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::ArtifactNotFound);
    fs::remove_dir_all(root).unwrap();
}

fn subject(source: &std::path::Path, digest: Digest) -> Subject {
    Subject {
        architecture: "x86-64".to_owned(),
        arguments: Vec::new(),
        artifact_digest: digest,
        artifact_media_type: "application/vnd.reproit.native-executable.v1".to_owned(),
        artifact_uri: format!("file://{}", source.display()),
        environment_names: Vec::new(),
        executable: "/subject".to_owned(),
        format: SubjectFormat::V1,
        operating_system: "linux".to_owned(),
        working_directory: "/work".to_owned(),
    }
}

fn temporary_root(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "reproit-subject-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    root
}
