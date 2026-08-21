use std::{
    collections::BTreeSet,
    fs,
    io::{Read as _, Write as _},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    str::FromStr,
    thread,
    time::Duration,
};

use reproit_backend::{
    checkpoint::{FileCheckpointConfig, FileCheckpointProvider},
    dependency::{DependencyTranscriptPool, HttpTranscriptProvider, HttpTranscriptReplay},
    world::{MaterializeRequest, StateProvider, TranscriptInteraction, with_verified_world},
};
use reproit_core::{
    ErrorCode,
    identity::{Digest, ExecutionId, ObjectId, OperationId, ServiceId, Timestamp},
    model::DependencyLimits,
};

#[test]
fn file_checkpoint_publishes_pretrigger_bytes_and_restores_repeatably() {
    let root = temporary_root("restore");
    let source = root.join("live.sqlite");
    fs::write(&source, b"counter=5\nabsent=true\norder=a,b,c").unwrap();
    let provider = provider(&root);
    let point = provider
        .publish(
            &source,
            1,
            timestamp("2026-01-01T00:00:00.000Z"),
            timestamp("2026-01-01T00:05:00.000Z"),
        )
        .unwrap();
    fs::write(&source, b"counter=25\nabsent=false\norder=c,b,a").unwrap();

    for index in 0..2 {
        let target = root.join("work").join(format!("restore-{index}.sqlite"));
        let restored = with_verified_world(
            &provider,
            &request(point.clone(), execution(index), &target),
            |_| Ok(fs::read(&target).unwrap()),
        )
        .unwrap();
        assert_eq!(restored, b"counter=5\nabsent=true\norder=a,b,c");
        assert!(!target.exists());
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn file_checkpoint_rejects_outside_targets_corruption_and_lease_exhaustion() {
    let root = temporary_root("negative");
    let source = root.join("checkpoint");
    fs::write(&source, b"checkpoint").unwrap();
    let mut config = config(&root);
    config.maximum_active_leases = 1;
    let provider = FileCheckpointProvider::open(config).unwrap();
    let point = provider
        .publish(
            &source,
            1,
            timestamp("2026-01-01T00:00:00.000Z"),
            timestamp("2026-01-01T00:05:00.000Z"),
        )
        .unwrap();

    let error = with_verified_world(
        &provider,
        &request(point.clone(), execution(0), &root.join("outside")),
        |_| Ok(()),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::StateScopeViolation);

    let first = provider
        .pin(
            &point,
            id("cap_01890f3e-7b1c-7cc0-8a1b-123456789abc"),
            Digest::of(b"world"),
        )
        .unwrap();
    let error = provider
        .pin(
            &point,
            id("cap_01890f3e-7b1c-7cc0-8a1b-123456789abd"),
            Digest::of(b"world"),
        )
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::RuntimeQuota);
    provider.release(&first).unwrap();

    let artifact = fs::read_dir(root.join("history"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().is_some_and(|value| value == "checkpoint"))
        .unwrap();
    fs::set_permissions(&artifact, writable_permissions()).unwrap();
    fs::write(&artifact, b"corrupt").unwrap();
    let error = provider
        .pin(
            &point,
            id("cap_01890f3e-7b1c-7cc0-8a1b-123456789abe"),
            Digest::of(b"world"),
        )
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::ObjectDigestMismatch);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn exact_http_transcript_preserves_order_identity_and_bounds() {
    let operation_id: OperationId = id("op_01890f3e-7b1c-7cc0-8a1b-123456789ab1");
    let request_id: ObjectId = id("obj_01890f3e-7b1c-7cc0-8a1b-123456789ab4");
    let response_id: ObjectId = id("obj_01890f3e-7b1c-7cc0-8a1b-123456789ab5");
    let request = b"GET /rate HTTP/1.1\r\n\r\n".to_vec();
    let response = b"HTTP/1.1 200 OK\r\n\r\n10".to_vec();
    let provider = HttpTranscriptProvider::new(1, 1024).unwrap();
    provider
        .record(
            TranscriptInteraction {
                causal_parent_id: None,
                operation_id,
                request_digest: Digest::of(&request),
                request_object_id: request_id,
                response_digest: Digest::of(&response),
                response_object_id: response_id,
                sequence: 0,
                session_position: 0,
            },
            request.clone(),
            response.clone(),
        )
        .unwrap();
    assert_eq!(provider.captured_bytes(), request.len() + response.len());
    let closed = provider.close(operation_id).unwrap();
    assert_eq!(closed.interactions.len(), 1);
    assert_eq!(closed.objects[&request_id], request);
    assert_eq!(closed.objects[&response_id], response);
    assert_eq!(provider.captured_bytes(), 0);

    let bounded = HttpTranscriptProvider::new(1, 4).unwrap();
    let error = bounded
        .record(
            closed.interactions[0].clone(),
            b"123".to_vec(),
            b"456".to_vec(),
        )
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::RuntimeQuota);
    assert_eq!(bounded.captured_bytes(), 0);
    assert!(
        HttpTranscriptProvider::new(
            usize::try_from(DependencyLimits::V1.interactions_per_operation).unwrap(),
            usize::try_from(DependencyLimits::V1.candidate_bytes + 1).unwrap(),
        )
        .is_err()
    );
}

#[test]
fn real_http_exchange_replays_exactly_without_live_network() {
    let operation_id: OperationId = id("op_01890f3e-7b1c-7cc0-8a1b-123456789ab1");
    let request =
        b"GET /rate HTTP/1.1\r\nHost: dependency.test\r\nConnection: close\r\n\r\n".to_vec();
    let expected_response =
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n10".to_vec();
    let (address, response) = one_local_http_exchange(&request, &expected_response);
    let transcript = capture_transcript(operation_id, request.clone(), response);

    let denial_listener = TcpListener::bind(address).expect("reserve the dependency address");
    denial_listener
        .set_nonblocking(true)
        .expect("make the dependency denial probe nonblocking");
    let mut replay = HttpTranscriptReplay::new(operation_id, transcript).unwrap();
    assert_eq!(
        replay.exchange(operation_id, &request).unwrap(),
        expected_response
    );
    assert_eq!(replay.consumed_interactions(), 1);
    assert_eq!(
        denial_listener
            .accept()
            .expect_err("replay must not contact the live dependency")
            .kind(),
        std::io::ErrorKind::WouldBlock
    );
    replay.finish().unwrap();
    drop(denial_listener);
    assert!(TcpListener::bind(address).is_ok());
}

#[test]
fn transcript_replay_rejects_missing_changed_extra_wrong_scope_and_corrupt_data() {
    let operation_id: OperationId = id("op_01890f3e-7b1c-7cc0-8a1b-123456789ab1");
    let other_operation: OperationId = id("op_01890f3e-7b1c-7cc0-8a1b-123456789ab2");
    let request = b"GET /rate HTTP/1.1\r\n\r\n".to_vec();
    let response = b"HTTP/1.1 200 OK\r\n\r\n10".to_vec();
    let transcript = capture_transcript(operation_id, request.clone(), response);

    assert_mismatch(
        HttpTranscriptReplay::new(operation_id, transcript.clone())
            .unwrap()
            .finish(),
    );
    let mut changed = HttpTranscriptReplay::new(operation_id, transcript.clone()).unwrap();
    assert_mismatch(changed.exchange(operation_id, b"GET /other HTTP/1.1\r\n\r\n"));
    assert_mismatch(changed.exchange(operation_id, &request));
    let mut wrong_scope = HttpTranscriptReplay::new(operation_id, transcript.clone()).unwrap();
    assert_mismatch(wrong_scope.exchange(other_operation, &request));
    let mut extra = HttpTranscriptReplay::new(operation_id, transcript.clone()).unwrap();
    extra.exchange(operation_id, &request).unwrap();
    assert_mismatch(extra.exchange(operation_id, &request));

    let mut corrupt = transcript.clone();
    let response_id = corrupt.interactions[0].response_object_id;
    corrupt.objects.insert(response_id, b"corrupt".to_vec());
    assert_mismatch(HttpTranscriptReplay::new(operation_id, corrupt));
    let mut unclosed = transcript;
    unclosed.objects.insert(
        id("obj_01890f3e-7b1c-7cc0-8a1b-123456789ab6"),
        b"orphan".to_vec(),
    );
    assert_mismatch(HttpTranscriptReplay::new(operation_id, unclosed));
}

#[test]
fn transcript_replay_restarts_from_the_immutable_beginning() {
    let operation_id: OperationId = id("op_01890f3e-7b1c-7cc0-8a1b-123456789ab1");
    let request = b"GET /rate HTTP/1.1\r\n\r\n".to_vec();
    let response = b"HTTP/1.1 200 OK\r\n\r\n10".to_vec();
    let transcript = capture_transcript(operation_id, request.clone(), response.clone());
    let mut interrupted = HttpTranscriptReplay::new(operation_id, transcript.clone()).unwrap();
    assert_eq!(
        interrupted.exchange(operation_id, &request).unwrap(),
        response
    );
    drop(interrupted);

    let mut restarted = HttpTranscriptReplay::new(operation_id, transcript).unwrap();
    assert_eq!(restarted.consumed_interactions(), 0);
    assert_eq!(
        restarted.exchange(operation_id, &request).unwrap(),
        response
    );
    restarted.finish().unwrap();
}

#[test]
fn dependency_fleet_reserves_before_work_and_releases_every_terminal_path() {
    let limits = DependencyLimits {
        active_operations: 1,
        candidate_bytes: 4,
        concurrent_close_requests: 1,
        cursor_lifetime_ms: 60_000,
        durable_bytes: 4,
        interactions_per_operation: 1,
        memory_bytes: 4,
        object_bytes: 4,
        sessions: 1,
    };
    let pool = DependencyTranscriptPool::new(limits).unwrap();
    let first = pool.open(1, 4).unwrap();
    let Err(error) = pool.open(1, 4) else {
        panic!("the second dependency operation must be rejected");
    };
    assert_eq!(error.code, ErrorCode::RuntimeQuota);
    first.discard();

    let failed_close = pool.open(1, 4).unwrap();
    assert_eq!(
        failed_close
            .close(id("op_01890f3e-7b1c-7cc0-8a1b-123456789ab1"))
            .unwrap_err()
            .code,
        ErrorCode::SchemaInvalid
    );
    drop(failed_close);
    drop(pool.open(1, 4).unwrap());
}

fn capture_transcript(
    operation_id: OperationId,
    request: Vec<u8>,
    response: Vec<u8>,
) -> reproit_backend::dependency::ClosedDependencyTranscript {
    let provider = HttpTranscriptProvider::new(1, 4_096).unwrap();
    provider
        .record(
            TranscriptInteraction {
                causal_parent_id: None,
                operation_id,
                request_digest: Digest::of(&request),
                request_object_id: id("obj_01890f3e-7b1c-7cc0-8a1b-123456789ab4"),
                response_digest: Digest::of(&response),
                response_object_id: id("obj_01890f3e-7b1c-7cc0-8a1b-123456789ab5"),
                sequence: 0,
                session_position: 0,
            },
            request,
            response,
        )
        .unwrap();
    provider.close(operation_id).unwrap()
}

fn one_local_http_exchange(request: &[u8], response: &[u8]) -> (SocketAddr, Vec<u8>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the local HTTP dependency");
    let address = listener
        .local_addr()
        .expect("local HTTP dependency address");
    let expected_request = request.to_vec();
    let response = response.to_vec();
    let server = thread::spawn(move || {
        let (mut connection, _) = listener.accept().expect("accept one HTTP request");
        connection
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("bound the HTTP dependency read");
        let mut actual_request = vec![0_u8; expected_request.len()];
        connection
            .read_exact(&mut actual_request)
            .expect("read one exact HTTP request");
        assert_eq!(actual_request, expected_request);
        connection
            .write_all(&response)
            .expect("write one exact HTTP response");
    });
    let mut connection = TcpStream::connect_timeout(&address, Duration::from_secs(1))
        .expect("connect to the local HTTP dependency");
    connection
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("bound the HTTP response read");
    connection
        .write_all(request)
        .expect("write the HTTP request");
    connection
        .shutdown(Shutdown::Write)
        .expect("finish the HTTP request");
    let mut actual_response = Vec::new();
    connection
        .take(4_097)
        .read_to_end(&mut actual_response)
        .expect("read the bounded HTTP response");
    assert!(actual_response.len() <= 4_096);
    server.join().expect("join the local HTTP dependency");
    (address, actual_response)
}

fn assert_mismatch<T>(result: Result<T, reproit_core::Error>) {
    let Err(error) = result else {
        panic!("The dependency transcript mismatch must fail");
    };
    assert_eq!(error.code, ErrorCode::DependencyTranscriptMismatch);
}

fn provider(root: &Path) -> FileCheckpointProvider {
    FileCheckpointProvider::open(config(root)).unwrap()
}

fn config(root: &Path) -> FileCheckpointConfig {
    FileCheckpointConfig::production(
        root.join("history"),
        root.join("work"),
        "orders-state".to_owned(),
        ServiceId::from_str("svc_01890f3e-7b1c-7cc0-8a1b-123456789abf").unwrap(),
        "sqlite".to_owned(),
        "3.53.4".to_owned(),
    )
}

fn request(
    point: reproit_backend::world::RecoverablePoint,
    execution_id: ExecutionId,
    target: &Path,
) -> MaterializeRequest {
    MaterializeRequest {
        capture_id: id("cap_01890f3e-7b1c-7cc0-8a1b-123456789abc"),
        execution_capabilities: BTreeSet::from(["checkpoint.file".to_owned()]),
        execution_id,
        now: timestamp("2026-01-01T00:00:30.000Z"),
        point,
        target_reference: target.display().to_string(),
        world_id: Digest::of(b"world"),
    }
}

fn execution(index: u8) -> ExecutionId {
    id(&format!(
        "exe_01890f3e-7b1c-7cc0-8a1b-123456789a{index:02x}"
    ))
}

fn timestamp(value: &str) -> Timestamp {
    Timestamp::from_str(value).unwrap()
}

fn id<T: FromStr>(value: &str) -> T
where
    T::Err: std::fmt::Debug,
{
    value.parse().unwrap()
}

#[cfg(unix)]
fn writable_permissions() -> fs::Permissions {
    use std::os::unix::fs::PermissionsExt as _;
    fs::Permissions::from_mode(0o600)
}

#[cfg(not(unix))]
#[expect(
    clippy::permissions_set_readonly_false,
    reason = "This branch uses the Windows read-only file attribute."
)]
fn writable_permissions() -> fs::Permissions {
    let mut permissions = fs::metadata(std::env::current_exe().unwrap())
        .unwrap()
        .permissions();
    permissions.set_readonly(false);
    permissions
}

fn temporary_root(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "reproit-provider-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    root
}
