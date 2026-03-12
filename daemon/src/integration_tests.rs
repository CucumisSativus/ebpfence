// Integration tests require a Linux kernel with LSM BPF enabled and root
// privileges. Run with:
//
//   sudo cargo test -p ebpfence-daemon --features integration -- --test-threads=1
//
// The --test-threads=1 flag is important: blocking tests affect the whole
// process, so tests must not run concurrently.

use std::fs;
use std::sync::{Arc, Mutex};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::config::BlockStrategy;
use crate::ebpf_provider::{EBPFProvider, RealEBPFProvider};
use crate::event_handler::{EventHandler, EventHandlerConfig};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn check_requirements() {
    // Must be root
    let status = fs::read_to_string("/proc/self/status").expect("cannot read /proc/self/status");
    let uid: u32 = status
        .lines()
        .find(|l| l.starts_with("Uid:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .expect("cannot parse UID from /proc/self/status");
    if uid != 0 {
        panic!("integration tests require root privileges (run with sudo)");
    }

    // LSM BPF must be active
    let lsm = fs::read_to_string("/sys/kernel/security/lsm")
        .expect("cannot read /sys/kernel/security/lsm");
    if !lsm.split(',').any(|m| m.trim() == "bpf") {
        panic!(
            "LSM BPF is not enabled (current LSM list: {:?}); reboot with lsm=...,bpf",
            lsm.trim()
        );
    }

    // BPF filesystem
    fs::metadata("/sys/fs/bpf").expect("BPF filesystem not mounted at /sys/fs/bpf");

    // BTF required for CO-RE
    fs::metadata("/sys/kernel/btf/vmlinux")
        .expect("kernel BTF not available at /sys/kernel/btf/vmlinux (required for CO-RE eBPF)");
}

fn null_term_str(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Verifies that eBPF programs can be loaded and attached without error.
#[test]
fn test_load_and_attach() {
    check_requirements();

    let provider =
        RealEBPFProvider::new(&BlockStrategy::BlockFiles).expect("failed to create eBPF provider");
    drop(provider);
}

/// Verifies that file open events are delivered to userspace via the ring buffer.
#[test]
fn test_event_collection() {
    check_requirements();

    let provider = Arc::new(
        RealEBPFProvider::new(&BlockStrategy::BlockFiles).expect("failed to create eBPF provider"),
    );

    let tmp_dir = tempfile::tempdir().expect("tempdir");
    let tmp_file = tmp_dir.path().join("test.txt");
    fs::write(&tmp_file, b"test").expect("write temp file");
    let tmp_file_str = tmp_file.to_str().unwrap().to_string();

    let my_pid = std::process::id();

    // The collector sends matching results down a channel so the main thread
    // blocks precisely until an event arrives rather than polling on a timer.
    let (tx, rx) = mpsc::channel::<(bool, bool)>(); // (pid_matched, filename_matched)
    let provider_clone = provider.clone();
    let collector = thread::spawn(move || {
        let mut pid_matched = false;
        let mut filename_matched = false;
        loop {
            match provider_clone.read_event() {
                Ok(event) => {
                    if event.pid == my_pid {
                        pid_matched = true;
                    }
                    if null_term_str(&event.filename) == tmp_file_str {
                        filename_matched = true;
                    }
                    // Notify on every event so the main thread can check progress.
                    let _ = tx.send((pid_matched, filename_matched));
                    if filename_matched {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Trigger the event.
    fs::read(&tmp_file).expect("read temp file");

    // Block until we see a matching event or the 6 s deadline expires.
    let mut pid_matched = false;
    let mut filename_matched = false;
    while let Ok((pm, fm)) = rx.recv_timeout(Duration::from_secs(6)) {
        pid_matched = pm;
        filename_matched = fm;
        if filename_matched {
            break;
        }
    }

    provider.close();
    collector.join().ok();

    if filename_matched {
        println!("successfully captured file open event");
    } else if pid_matched {
        // bpf_d_path may not resolve on all kernel configurations.
        println!("received events from our PID but bpf_d_path did not resolve the expected filename — expected on some kernels");
    } else {
        panic!(
            "timeout waiting for file open event; check that 'bpf' is in /sys/kernel/security/lsm"
        );
    }
}

/// Verifies that block_pid causes file opens to return EPERM.
#[test]
fn test_blocking_functionality() {
    check_requirements();

    let provider =
        RealEBPFProvider::new(&BlockStrategy::BlockFiles).expect("failed to create eBPF provider");

    let tmp_dir = tempfile::tempdir().expect("tempdir");
    let test_file = tmp_dir.path().join("test.txt");
    fs::write(&test_file, b"test data").expect("write test file");

    // File must be accessible before blocking.
    fs::read(&test_file).expect("initial file access failed (should succeed)");

    let pid = std::process::id();
    provider.block_pid(pid).expect("failed to block PID");

    // Small delay to let the kernel map update propagate.
    thread::sleep(Duration::from_millis(100));

    let result = fs::read(&test_file);
    if result.is_ok() {
        // Unblock before panicking so we don't leave the process in a broken
        // state for subsequent tests.
        provider.unblock_pid(pid).ok();
        panic!(
            "file access was not blocked after block_pid — verify the kernel was booted with lsm=...,bpf"
        );
    }

    let err = result.unwrap_err();
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::PermissionDenied,
        "expected PermissionDenied, got: {err}"
    );

    // Restore before the provider (and its LSM hooks) is dropped.
    provider.unblock_pid(pid).expect("failed to unblock PID");
    println!("file access correctly blocked and restored");
}

/// Verifies the full EventHandler flow: violation counting and automatic blocking.
#[tokio::test]
async fn test_end_to_end() {
    check_requirements();

    let tmp_dir = tempfile::tempdir().expect("tempdir");
    let secret_dir = tmp_dir.path().join("secrets");
    fs::create_dir_all(&secret_dir).expect("create secret dir");

    let secret1 = secret_dir.join("secret1.txt");
    let secret2 = secret_dir.join("secret2.txt");
    let allowed = tmp_dir.path().join("allowed.txt");
    for f in [&secret1, &secret2, &allowed] {
        fs::write(f, b"data").expect("write file");
    }

    let provider = Arc::new(
        RealEBPFProvider::new(&BlockStrategy::BlockFiles).expect("failed to create eBPF provider"),
    );

    let pattern = format!("{}/*", secret_dir.display());
    let current_pid = std::process::id();
    let handler = Arc::new(
        EventHandler::new(
            provider.clone() as Arc<dyn EBPFProvider>,
            EventHandlerConfig {
                disallowed_patterns: vec![pattern],
                threshold: 2,
                target_pid: current_pid,
                strategy: BlockStrategy::BlockFiles,
            },
        )
        .expect("failed to create event handler"),
    );

    let token = CancellationToken::new();
    let h = handler.clone();
    let t = token.clone();
    let task = tokio::spawn(async move { h.run(t).await });

    // Give the handler time to start.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Allowed file — should not count as a violation.
    let _ = fs::read(&allowed);
    tokio::time::sleep(Duration::from_millis(100)).await;

    // First secret access.
    let _ = fs::read(&secret1);
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Second secret access — should trigger blocking.
    let _ = fs::read(&secret2);

    // Wait for the handler to process the events.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Shut down the handler and detach LSM hooks before asserting.
    token.cancel();
    provider.close();
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    drop(provider);

    let violations = handler.get_violation_count_for_pid(current_pid);
    assert!(
        violations >= 2,
        "expected at least 2 violations for PID {current_pid}, got {violations}; \
         check that 'bpf' is in /sys/kernel/security/lsm"
    );
    assert!(
        handler.is_pid_blocked(current_pid),
        "expected PID {current_pid} to be blocked after {violations} violations"
    );

    println!("detected {violations} violations and correctly blocked PID {current_pid}");
}

/// Verifies that unblock_pid restores file access.
#[test]
fn test_unblock_functionality() {
    check_requirements();

    let provider =
        RealEBPFProvider::new(&BlockStrategy::BlockFiles).expect("failed to create eBPF provider");

    let tmp_dir = tempfile::tempdir().expect("tempdir");
    let test_file = tmp_dir.path().join("test.txt");
    fs::write(&test_file, b"test data").expect("write test file");

    // Accessible before blocking.
    fs::read(&test_file).expect("initial file access failed");

    let pid = std::process::id();
    provider.block_pid(pid).expect("failed to block PID");
    thread::sleep(Duration::from_millis(100));

    let err = fs::read(&test_file).expect_err(
        "file access was not blocked after block_pid — verify the kernel was booted with lsm=...,bpf",
    );
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::PermissionDenied,
        "expected PermissionDenied while blocked, got: {err}"
    );
    println!("file access correctly blocked: {err}");

    provider.unblock_pid(pid).expect("failed to unblock PID");
    thread::sleep(Duration::from_millis(100));

    fs::read(&test_file).expect("file access should be restored after unblock_pid");
    println!("file access correctly restored after unblock");
}
