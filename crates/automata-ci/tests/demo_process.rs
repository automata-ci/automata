#![cfg(windows)]

use std::{
    fs,
    io::{Read as _, Write as _},
    net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

// A cold debug build may spend about a minute initializing the embedded SSR runtime.
const WAIT_LIMIT: Duration = Duration::from_mins(2);

#[test]
fn shipped_demo_explains_success_and_failure_in_the_standard_ui_and_cleans_up() {
    let fixture = Fixture::new();

    let mut success = fixture.run(
        "success",
        r"name: Acceptance success
on: workflow_dispatch
jobs:
  acceptance:
    runs-on: windows
    steps:
      - name: Produce evidence
        shell: powershell
        run: Start-Sleep -Seconds 2; Write-Output 'native acceptance output'
      - name: Verify evidence
        shell: cmd
        run: echo verification complete
",
    );
    let active = success.wait_for_page("Step 1/2 running: Produce evidence [powershell]");
    assert!(active.headers.contains("refresh: 1"));
    assert_standard_ui(&active.body);

    let completed = success.wait_for_page("Evaluation succeeded: every step exited successfully");
    assert!(!completed.headers.contains("refresh:"));
    assert!(completed.body.contains("native acceptance output"));
    assert!(
        completed
            .body
            .contains("Step 1 succeeded: Produce evidence — exit 0")
    );
    assert!(
        completed
            .body
            .contains("Step 2 succeeded: Verify evidence — exit 0")
    );
    assert!(completed.body.contains("Disposable workspace removed"));
    fixture.assert_no_demo_workspaces();
    success.stop();

    let mut failure = fixture.run(
        "failure",
        r"name: Acceptance failure
on: workflow_dispatch
jobs:
  acceptance:
    runs-on: windows
    steps:
      - name: Deliberate failure
        shell: cmd
        run: echo expected failure 1>&2 & exit /b 7
",
    );
    let failed = failure.wait_for_page("Step 1 failed: Deliberate failure — exit 7");
    assert_standard_ui(&failed.body);
    assert!(failed.body.contains("expected failure"));
    assert!(failed.body.contains("Demo workflow failed:"));
    assert!(failed.body.contains("Disposable workspace removed"));
    assert!(!failed.headers.contains("refresh:"));
    fixture.assert_no_demo_workspaces();
    failure.stop();

    let unsupported_repository = fixture.root.join("unsupported");
    let unsupported_workflow_directory = unsupported_repository.join(".ci/workflows");
    fs::create_dir_all(&unsupported_workflow_directory)
        .expect("create unsupported workflow directory");
    fs::write(
        unsupported_workflow_directory.join("acceptance.yml"),
        r"name: Unsupported action
on: workflow_dispatch
jobs:
  acceptance:
    runs-on: windows
    steps:
      - uses: actions/checkout@v4
",
    )
    .expect("write unsupported workflow");
    let rejected = Command::new(env!("CARGO_BIN_EXE_automata"))
        .args([
            "demo",
            "--repo",
            unsupported_repository
                .to_str()
                .expect("Unicode unsupported fixture path"),
            "--workflow",
            ".ci/workflows/acceptance.yml",
            "--allow-host-execution",
            "--no-visual",
        ])
        .output()
        .expect("run unsupported workflow through shipped binary");
    assert!(!rejected.status.success());
    let rejection = String::from_utf8_lossy(&rejected.stderr);
    assert!(
        rejection.contains("rejects every uses: action"),
        "{rejection}"
    );
    fixture.assert_no_demo_workspaces();
}

fn assert_standard_ui(body: &str) {
    assert!(body.contains("Trusted Windows host execution logs · Automata"));
    assert!(body.contains("aria-label=\"Run navigation\""));
    assert!(body.contains("placeholder=\"Search logs\""));
    assert!(body.contains("aria-label=\"Color theme\""));
    assert!(body.contains(
        "Evaluation started: commands run through a Windows Job Object as the current Windows user"
    ));
    assert!(body.contains("Plan accepted:"));
}

struct Fixture {
    root: PathBuf,
    initial_demo_workspaces: Vec<String>,
}

impl Fixture {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "automata-demo-process-test-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create process-test root");
        Self {
            root,
            initial_demo_workspaces: demo_workspaces(),
        }
    }

    fn run(&self, name: &str, workflow: &str) -> RunningDemo {
        let repository = self.root.join(name);
        let workflow_directory = repository.join(".ci/workflows");
        fs::create_dir_all(&workflow_directory).expect("create workflow directory");
        fs::write(workflow_directory.join("acceptance.yml"), workflow)
            .expect("write acceptance workflow");

        let port = available_port();
        let child = Command::new(env!("CARGO_BIN_EXE_automata"))
            .args([
                "demo",
                "--repo",
                repository.to_str().expect("Unicode fixture path"),
                "--workflow",
                ".ci/workflows/acceptance.yml",
                "--allow-host-execution",
                "--listen",
                &format!("127.0.0.1:{port}"),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("launch shipped automata binary");
        RunningDemo { child, port }
    }

    fn assert_no_demo_workspaces(&self) {
        assert_eq!(
            demo_workspaces(),
            self.initial_demo_workspaces,
            "the shipped demo must remove its temporary workspace"
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct RunningDemo {
    child: Child,
    port: u16,
}

impl RunningDemo {
    fn wait_for_page(&mut self, expected: &str) -> HttpResponse {
        let deadline = Instant::now() + WAIT_LIMIT;
        let mut last = String::new();
        while Instant::now() < deadline {
            if let Ok(entry) = http_get(self.port, "/__demo") {
                last = format!(
                    "entry headers:\n{}\nentry body:\n{}",
                    entry.headers, entry.body
                );
                if let Some(location) = header(&entry.headers, "location")
                    && let Ok(page) = http_get(self.port, location)
                {
                    last = format!("page headers:\n{}\npage body:\n{}", page.headers, page.body);
                    if page.body.contains(expected) {
                        return page;
                    }
                }
            }
            if let Some(status) = self.child.try_wait().expect("inspect demo process") {
                panic!("demo process exited with {status}; last response: {last}");
            }
            thread::sleep(Duration::from_millis(100));
        }
        let diagnostics = self.diagnostics();
        panic!(
            "timed out waiting for `{expected}`; last response: {last}; process output: {diagnostics}"
        );
    }

    fn diagnostics(&mut self) -> String {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let mut output = String::new();
        if let Some(mut stdout) = self.child.stdout.take() {
            let _ = stdout.read_to_string(&mut output);
        }
        if let Some(mut stderr) = self.child.stderr.take() {
            let _ = stderr.read_to_string(&mut output);
        }
        output
    }

    fn stop(mut self) {
        self.terminate();
    }

    fn terminate(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            self.child.kill().expect("terminate demo process");
        }
        self.child.wait().expect("reap demo process");
    }
}

impl Drop for RunningDemo {
    fn drop(&mut self) {
        self.terminate();
    }
}

struct HttpResponse {
    headers: String,
    body: String,
}

fn http_get(port: u16, path: &str) -> std::io::Result<HttpResponse> {
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
    )?;
    let mut bytes = Vec::new();
    loop {
        let mut buffer = [0_u8; 16 * 1024];
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => bytes.extend_from_slice(&buffer[..count]),
            Err(error)
                if !bytes.is_empty()
                    && matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
            {
                break;
            }
            Err(error) => return Err(error),
        }
    }
    let response = String::from_utf8_lossy(&bytes);
    let (headers, body) = response.split_once("\r\n\r\n").unwrap_or((&response, ""));
    Ok(HttpResponse {
        headers: headers.to_ascii_lowercase(),
        body: body.to_owned(),
    })
}

fn header<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    headers.lines().find_map(|line| {
        let (candidate, value) = line.split_once(':')?;
        candidate.eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

fn demo_workspaces() -> Vec<String> {
    let mut workspaces = fs::read_dir(std::env::temp_dir())
        .expect("read system temporary directory")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| {
            name.starts_with("automata-demo-") && !name.starts_with("automata-demo-process-test-")
        })
        .collect::<Vec<_>>();
    workspaces.sort();
    workspaces
}

fn available_port() -> u16 {
    TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .expect("reserve loopback port")
        .local_addr()
        .expect("inspect loopback reservation")
        .port()
}
