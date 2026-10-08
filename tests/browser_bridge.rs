//! End to end over real processes: a fake app drives `mpx bridge` through
//! its stdin/stdout while `mpx browser` talks to the socket it serves.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn mpx() -> Command {
    Command::new(env!("CARGO_BIN_EXE_mpx"))
}

#[test]
fn a_browser_request_round_trips_through_the_bridge() {
    let dir = tempfile::tempdir().unwrap();
    let mut bridge = mpx()
        .args(["bridge", "--device", "Test iPad"])
        .env("MPX_RUNTIME_DIR", dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut app_out = bridge.stdin.take().unwrap();
    let mut app_in = BufReader::new(bridge.stdout.take().unwrap());

    let mut hello = String::new();
    app_in.read_line(&mut hello).unwrap();
    let hello: Value = serde_json::from_str(&hello).unwrap();
    assert_eq!(hello["mpx"], "browser-bridge");
    let socket = dir.path().join("browser-test-ipad.sock");
    assert_eq!(hello["socket"], socket.display().to_string());

    // The fake app: answer exactly one request, echoing what it was asked.
    let app = std::thread::spawn(move || {
        let mut line = String::new();
        app_in.read_line(&mut line).unwrap();
        let request: Value = serde_json::from_str(&line).unwrap();
        let answer = json!({
            "id": request["id"],
            "result": { "tab": "t1", "url": request["params"]["url"], "title": request["method"] }
        });
        writeln!(app_out, "{answer}").unwrap();
        app_out.flush().unwrap();
        (app_out, app_in)
    });

    let output = mpx()
        .args([
            "browser",
            "open",
            "http://localhost:3000/",
            "--session",
            "work",
        ])
        .env("MPX_RUNTIME_DIR", dir.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "t1  http://localhost:3000/  open"
    );

    // Closing the app's side ends the bridge and takes the socket with it.
    let (app_out, _app_in) = app.join().unwrap();
    drop(app_out);
    let deadline = Instant::now() + Duration::from_secs(5);
    while bridge.try_wait().unwrap().is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        bridge.try_wait().unwrap().is_some(),
        "bridge outlived its app"
    );
    assert!(!socket.exists());
}

#[test]
fn no_bridge_is_an_actionable_error() {
    let dir = tempfile::tempdir().unwrap();
    let output = mpx()
        .args(["browser", "tabs"])
        .env("MPX_RUNTIME_DIR", dir.path())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Agent Browser"));
}

#[test]
fn a_terminated_bridge_takes_its_socket_and_ids_separate_twins() {
    let dir = tempfile::tempdir().unwrap();
    let spawn = |id: &str| {
        let mut child = mpx()
            .args(["bridge", "--device", "iPad", "--id", id])
            .env("MPX_RUNTIME_DIR", dir.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut hello = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut hello)
            .unwrap();
        (child, hello)
    };
    let (mut first, hello) = spawn("3f2a9c1e");
    assert!(hello.contains("browser-ipad-3f2a9c1e.sock"), "{hello}");
    let (mut second, _) = spawn("77aa00bb");
    let first_socket = dir.path().join("browser-ipad-3f2a9c1e.sock");
    let second_socket = dir.path().join("browser-ipad-77aa00bb.sock");
    assert!(
        first_socket.exists() && second_socket.exists(),
        "twins must not evict each other"
    );

    // SAFETY: plain kill(2) on our own child.
    unsafe { libc::kill(first.id() as i32, libc::SIGTERM) };
    let deadline = Instant::now() + Duration::from_secs(5);
    while first.try_wait().unwrap().is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        !first_socket.exists(),
        "the terminated bridge left its socket"
    );
    assert!(second_socket.exists());
    let _ = second.kill();
}
