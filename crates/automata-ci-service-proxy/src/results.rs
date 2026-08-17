use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use rustix::net::{AddressFamily, SocketFlags, SocketType, bind, ipproto, listen, socket_with};

use crate::config::ResultsConfiguration;
use crate::error::ProxyError;
use crate::limit::{SlotLimiter, SlotPermit};

pub(crate) const RESULTS_PORT: u16 = 8081;
const RESULTS_BACKLOG: i32 = 16;
const MAX_RESULTS_SESSIONS: usize = 32;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_mins(5);
const HALF_CLOSE_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const RELAY_THREAD_STACK_BYTES: usize = 128 * 1024;
const RELAY_BUFFER_BYTES: usize = 16 * 1024;

pub(crate) struct ResultsProxy {
    listener: TcpListener,
    configuration: ResultsConfiguration,
    sessions: Arc<SlotLimiter>,
}

impl ResultsProxy {
    pub(crate) fn prepare(configuration: ResultsConfiguration) -> Result<Self, ProxyError> {
        let socket = socket_with(
            AddressFamily::INET,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            Some(ipproto::TCP),
        )
        .map_err(|_| ProxyError::Bind)?;
        let address = SocketAddrV4::new(configuration.front_address(), RESULTS_PORT);
        bind(&socket, &address).map_err(|_| ProxyError::Bind)?;
        listen(&socket, RESULTS_BACKLOG).map_err(|_| ProxyError::Bind)?;
        let listener = TcpListener::from(socket);
        if listener.local_addr().ok() != Some(SocketAddr::V4(address)) {
            return Err(ProxyError::Bind);
        }
        Ok(Self {
            listener,
            configuration,
            sessions: Arc::new(SlotLimiter::new(MAX_RESULTS_SESSIONS)),
        })
    }

    pub(crate) fn run(self) -> Result<(), ProxyError> {
        loop {
            let (client, peer) = match self.listener.accept() {
                Ok(accepted) => accepted,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(ProxyError::Runtime),
            };
            if peer.ip() != self.configuration.job_address()
                || client.local_addr().ok()
                    != Some(SocketAddr::V4(SocketAddrV4::new(
                        self.configuration.front_address(),
                        RESULTS_PORT,
                    )))
            {
                continue;
            }
            let Some(permit) = self.sessions.try_acquire() else {
                continue;
            };
            spawn_session(client, self.configuration.target_address(), permit);
        }
    }
}

fn spawn_session(client: TcpStream, target: Ipv4Addr, permit: SlotPermit) {
    let session = move || relay_session(client, target, permit);
    let _ = thread::Builder::new()
        .name("results-proxy-session".to_owned())
        .stack_size(RELAY_THREAD_STACK_BYTES)
        .spawn(session);
}

fn relay_session(client: TcpStream, target: Ipv4Addr, _permit: SlotPermit) {
    let Ok(upstream) = TcpStream::connect_timeout(
        &SocketAddr::V4(SocketAddrV4::new(target, RESULTS_PORT)),
        CONNECT_TIMEOUT,
    ) else {
        return;
    };
    relay_connected(
        client,
        upstream,
        SESSION_IDLE_TIMEOUT,
        HALF_CLOSE_DRAIN_TIMEOUT,
    );
}

#[derive(Clone, Copy)]
enum PumpDirection {
    Request,
    Response,
}

struct RelayTiming {
    last_activity: Instant,
    response_half_closed_at: Option<Instant>,
}

struct RelayState {
    timing: Mutex<RelayTiming>,
    pumps_finished: AtomicUsize,
    pump_failed: AtomicBool,
    wake: mpsc::SyncSender<()>,
}

impl RelayState {
    fn new(wake: mpsc::SyncSender<()>) -> Self {
        Self {
            timing: Mutex::new(RelayTiming {
                last_activity: Instant::now(),
                response_half_closed_at: None,
            }),
            pumps_finished: AtomicUsize::new(0),
            pump_failed: AtomicBool::new(false),
            wake,
        }
    }

    fn record_activity(&self) {
        self.timing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .last_activity = Instant::now();
        let _ = self.wake.try_send(());
    }

    fn record_completion(&self, direction: PumpDirection, succeeded: bool) {
        if !succeeded {
            self.pump_failed.store(true, Ordering::SeqCst);
        } else if matches!(direction, PumpDirection::Response) {
            self.timing
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .response_half_closed_at = Some(Instant::now());
        }
        self.pumps_finished.fetch_add(1, Ordering::SeqCst);
        let _ = self.wake.try_send(());
    }

    fn remaining(
        &self,
        session_idle_timeout: Duration,
        response_drain_timeout: Duration,
    ) -> Duration {
        let timing = self
            .timing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let session_remaining = session_idle_timeout.saturating_sub(timing.last_activity.elapsed());
        let drain_remaining =
            timing
                .response_half_closed_at
                .map_or(session_remaining, |closed_at| {
                    response_drain_timeout
                        .saturating_sub(timing.last_activity.max(closed_at).elapsed())
                });
        session_remaining.min(drain_remaining)
    }
}

fn relay_connected(
    client: TcpStream,
    upstream: TcpStream,
    session_idle_timeout: Duration,
    response_drain_timeout: Duration,
) {
    let client = Arc::new(client);
    let upstream = Arc::new(upstream);
    let (wake, wait_for_activity) = mpsc::sync_channel(1);
    let state = Arc::new(RelayState::new(wake));
    let Ok(client_to_upstream) = spawn_pump(
        "results-proxy-request",
        PumpDirection::Request,
        Arc::clone(&client),
        Arc::clone(&upstream),
        Arc::clone(&state),
    ) else {
        return;
    };
    let Ok(upstream_to_client) = spawn_pump(
        "results-proxy-response",
        PumpDirection::Response,
        Arc::clone(&upstream),
        Arc::clone(&client),
        Arc::clone(&state),
    ) else {
        let _ = client.shutdown(Shutdown::Both);
        let _ = upstream.shutdown(Shutdown::Both);
        let _ = client_to_upstream.join();
        return;
    };

    loop {
        if state.pump_failed.load(Ordering::SeqCst)
            || state.pumps_finished.load(Ordering::SeqCst) == 2
        {
            break;
        }
        let remaining = state.remaining(session_idle_timeout, response_drain_timeout);
        if remaining.is_zero() {
            break;
        }
        match wait_for_activity.recv_timeout(remaining) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    let _ = client.shutdown(Shutdown::Both);
    let _ = upstream.shutdown(Shutdown::Both);
    let _ = client_to_upstream.join();
    let _ = upstream_to_client.join();
}

fn spawn_pump(
    name: &str,
    direction: PumpDirection,
    source: Arc<TcpStream>,
    destination: Arc<TcpStream>,
    state: Arc<RelayState>,
) -> io::Result<thread::JoinHandle<()>> {
    thread::Builder::new()
        .name(name.to_owned())
        .stack_size(RELAY_THREAD_STACK_BYTES)
        .spawn(move || {
            let mut source = &*source;
            let mut destination = &*destination;
            let succeeded = pump(&mut source, &mut destination, &state).is_ok()
                && destination.shutdown(Shutdown::Write).is_ok();
            state.record_completion(direction, succeeded);
        })
}

fn pump(
    source: &mut &TcpStream,
    destination: &mut &TcpStream,
    state: &RelayState,
) -> io::Result<()> {
    let mut buffer = [0_u8; RELAY_BUFFER_BYTES];
    loop {
        let size = match source.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(size) => size,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        state.record_activity();
        let mut written = 0;
        while written < size {
            match destination.write(&buffer[written..size]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "Results relay write made no progress",
                    ));
                }
                Ok(size) => {
                    written += size;
                    state.record_activity();
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_IDLE_TIMEOUT: Duration = Duration::from_millis(400);
    const TEST_DRAIN_TIMEOUT: Duration = Duration::from_millis(160);
    const TEST_ACTIVITY_INTERVAL: Duration = Duration::from_millis(50);
    const TEST_RESPONSE_DELAY: Duration = Duration::from_millis(250);
    const TEST_COMPLETION_TIMEOUT: Duration = Duration::from_secs(3);

    fn connected_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind test listener");
        let connector = TcpStream::connect(listener.local_addr().expect("listener address"))
            .expect("connect test socket");
        let accepted = listener.accept().expect("accept test socket").0;
        connector
            .set_read_timeout(Some(TEST_COMPLETION_TIMEOUT))
            .expect("set connector read timeout");
        connector
            .set_write_timeout(Some(TEST_COMPLETION_TIMEOUT))
            .expect("set connector write timeout");
        accepted
            .set_read_timeout(Some(TEST_COMPLETION_TIMEOUT))
            .expect("set accepted read timeout");
        accepted
            .set_write_timeout(Some(TEST_COMPLETION_TIMEOUT))
            .expect("set accepted write timeout");
        (connector, accepted)
    }

    fn test_relay(idle_timeout: Duration) -> (TcpStream, TcpStream, mpsc::Receiver<()>) {
        let (client, relay_client) = connected_pair();
        let (relay_upstream, target) = connected_pair();
        let (finished, wait_for_relay) = mpsc::channel();
        thread::spawn(move || {
            relay_connected(
                relay_client,
                relay_upstream,
                idle_timeout,
                TEST_DRAIN_TIMEOUT,
            );
            let _ = finished.send(());
        });
        (client, target, wait_for_relay)
    }

    #[test]
    fn results_transport_contract_is_fixed() {
        assert_eq!(RESULTS_PORT, 8081);
        assert_eq!(RESULTS_BACKLOG, 16);
        assert_eq!(MAX_RESULTS_SESSIONS, 32);
        assert_eq!(CONNECT_TIMEOUT, Duration::from_secs(5));
        assert_eq!(SESSION_IDLE_TIMEOUT, Duration::from_mins(5));
        assert_eq!(HALF_CLOSE_DRAIN_TIMEOUT, Duration::from_secs(5));
        assert_eq!(RELAY_BUFFER_BYTES, 16 * 1024);
    }

    #[test]
    fn request_half_close_preserves_a_delayed_response() {
        let (mut client, mut target, wait_for_relay) = test_relay(TEST_IDLE_TIMEOUT);
        client.write_all(b"request").expect("write request");
        client
            .shutdown(Shutdown::Write)
            .expect("close request half");

        let mut request = Vec::new();
        target.read_to_end(&mut request).expect("read request");
        assert_eq!(request, b"request");
        thread::sleep(TEST_RESPONSE_DELAY);
        target.write_all(b"response").expect("write response");
        target
            .shutdown(Shutdown::Write)
            .expect("close response half");

        let mut response = Vec::new();
        client.read_to_end(&mut response).expect("read response");
        assert_eq!(response, b"response");
        wait_for_relay
            .recv_timeout(TEST_COMPLETION_TIMEOUT)
            .expect("relay completed");
    }

    #[test]
    fn active_one_way_upload_refreshes_the_shared_idle_deadline() {
        let (mut client, mut target, wait_for_relay) = test_relay(TEST_IDLE_TIMEOUT);
        target
            .shutdown(Shutdown::Write)
            .expect("close response half");
        let mut response_eof = [0_u8; 1];
        assert_eq!(
            client.read(&mut response_eof).expect("read response EOF"),
            0
        );

        for (index, byte) in b"upload".iter().enumerate() {
            client.write_all(&[*byte]).expect("write request byte");
            let mut received = [0_u8; 1];
            target.read_exact(&mut received).expect("read request byte");
            assert_eq!(received[0], *byte);
            if index + 1 < b"upload".len() {
                thread::sleep(TEST_ACTIVITY_INTERVAL);
            }
        }
        client
            .shutdown(Shutdown::Write)
            .expect("close request half");
        let mut request_eof = [0_u8; 1];
        assert_eq!(target.read(&mut request_eof).expect("read request EOF"), 0);
        wait_for_relay
            .recv_timeout(TEST_COMPLETION_TIMEOUT)
            .expect("relay completed");
    }

    #[test]
    fn active_one_way_response_refreshes_the_shared_idle_deadline() {
        let (mut client, mut target, wait_for_relay) = test_relay(TEST_IDLE_TIMEOUT);
        client
            .shutdown(Shutdown::Write)
            .expect("close request half");
        let mut request_eof = [0_u8; 1];
        assert_eq!(target.read(&mut request_eof).expect("read request EOF"), 0);

        for (index, byte) in b"responses!".iter().enumerate() {
            target.write_all(&[*byte]).expect("write response byte");
            let mut received = [0_u8; 1];
            client
                .read_exact(&mut received)
                .expect("read response byte");
            assert_eq!(received[0], *byte);
            if index + 1 < b"responses!".len() {
                thread::sleep(TEST_ACTIVITY_INTERVAL);
            }
        }
        target
            .shutdown(Shutdown::Write)
            .expect("close response half");
        let mut response_eof = [0_u8; 1];
        assert_eq!(
            client.read(&mut response_eof).expect("read response EOF"),
            0
        );
        wait_for_relay
            .recv_timeout(TEST_COMPLETION_TIMEOUT)
            .expect("relay completed");
    }

    #[test]
    fn genuinely_idle_session_is_reaped() {
        let (_client, _target, wait_for_relay) = test_relay(TEST_IDLE_TIMEOUT);
        assert!(matches!(
            wait_for_relay.recv_timeout(TEST_IDLE_TIMEOUT / 3),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        wait_for_relay
            .recv_timeout(TEST_COMPLETION_TIMEOUT)
            .expect("idle relay completed");
    }

    #[test]
    fn inactive_request_half_is_reaped_after_response_half_close() {
        let (mut client, target, wait_for_relay) = test_relay(Duration::from_secs(2));
        target
            .shutdown(Shutdown::Write)
            .expect("close response half");
        let mut response_eof = [0_u8; 1];
        assert_eq!(
            client.read(&mut response_eof).expect("read response EOF"),
            0
        );
        assert!(matches!(
            wait_for_relay.recv_timeout(TEST_DRAIN_TIMEOUT / 3),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        wait_for_relay
            .recv_timeout(TEST_COMPLETION_TIMEOUT)
            .expect("inactive request drain completed");
    }
}
