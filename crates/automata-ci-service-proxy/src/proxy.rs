use std::collections::HashMap;
use std::io;
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use rustix::event::{Timespec, epoll};

use crate::config::{MAX_LISTENERS, Mapping, Transport};
use crate::error::ProxyError;
use crate::limit::{SlotLimiter, SlotPermit};

const LOOPBACK: Ipv4Addr = Ipv4Addr::LOCALHOST;
const MAX_TCP_SESSIONS: usize = 64;
const MAX_UDP_ASSOCIATIONS: usize = 64;
const MAX_EPOLL_EVENTS: usize = MAX_LISTENERS + MAX_UDP_ASSOCIATIONS;
const MAX_ACCEPTS_PER_EVENT: usize = 64;
const MAX_DATAGRAMS_PER_EVENT: usize = 64;
const MAX_UDP_DATAGRAM_BYTES: usize = 65_507;
const UDP_ASSOCIATION_IDLE: Duration = Duration::from_secs(30);
const EVENT_POLL_INTERVAL: Duration = Duration::from_secs(1);
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const TCP_HALF_CLOSE_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const RELAY_THREAD_STACK_BYTES: usize = 128 * 1024;
const ASSOCIATION_TOKEN_FLAG: u64 = 1_u64 << 63;

enum BoundListener {
    Tcp {
        socket: TcpListener,
        target: SocketAddrV4,
    },
    Udp {
        socket: UdpSocket,
        target: SocketAddrV4,
    },
}

impl BoundListener {
    fn port(&self) -> Result<u16, ProxyError> {
        let address = match self {
            Self::Tcp { socket, .. } => socket.local_addr(),
            Self::Udp { socket, .. } => socket.local_addr(),
        }
        .map_err(|_| ProxyError::Bind)?;
        match address {
            SocketAddr::V4(address) if *address.ip() == LOOPBACK && address.port() != 0 => {
                Ok(address.port())
            }
            _ => Err(ProxyError::Bind),
        }
    }

    fn register(&self, poller: &impl std::os::fd::AsFd, token: u64) -> Result<(), ProxyError> {
        let result = match self {
            Self::Tcp { socket, .. } => epoll::add(
                poller,
                socket,
                epoll::EventData::new_u64(token),
                epoll::EventFlags::IN,
            ),
            Self::Udp { socket, .. } => epoll::add(
                poller,
                socket,
                epoll::EventData::new_u64(token),
                epoll::EventFlags::IN,
            ),
        };
        result.map_err(|_| ProxyError::Bind)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct AssociationKey {
    listener_index: usize,
    client: SocketAddrV4,
}

struct UdpAssociation {
    socket: UdpSocket,
    token: u64,
    last_client_activity: Instant,
}

pub(crate) struct PreparedProxy {
    poller: std::os::fd::OwnedFd,
    listeners: Vec<BoundListener>,
    tcp_sessions: Arc<SlotLimiter>,
    udp_association_limit: usize,
    udp_association_idle: Duration,
    udp_associations: HashMap<AssociationKey, UdpAssociation>,
    udp_tokens: HashMap<u64, AssociationKey>,
    next_udp_token: u64,
    udp_datagram: Vec<u8>,
}

impl PreparedProxy {
    pub(crate) fn prepare(mappings: &[Mapping]) -> Result<Self, ProxyError> {
        Self::prepare_with_limits(
            mappings,
            MAX_TCP_SESSIONS,
            MAX_UDP_ASSOCIATIONS,
            UDP_ASSOCIATION_IDLE,
        )
    }

    fn prepare_with_limits(
        mappings: &[Mapping],
        tcp_session_limit: usize,
        udp_association_limit: usize,
        udp_association_idle: Duration,
    ) -> Result<Self, ProxyError> {
        let listeners = bind_all(mappings)?;
        let poller = epoll::create(epoll::CreateFlags::CLOEXEC).map_err(|_| ProxyError::Bind)?;
        for (index, listener) in listeners.iter().enumerate() {
            listener.register(&poller, index as u64)?;
        }

        Ok(Self {
            poller,
            listeners,
            tcp_sessions: Arc::new(SlotLimiter::new(tcp_session_limit)),
            udp_association_limit,
            udp_association_idle,
            udp_associations: HashMap::with_capacity(udp_association_limit),
            udp_tokens: HashMap::with_capacity(udp_association_limit),
            next_udp_token: 1,
            udp_datagram: vec![0_u8; MAX_UDP_DATAGRAM_BYTES],
        })
    }

    pub(crate) fn ports(&self) -> Result<Vec<u16>, ProxyError> {
        self.listeners.iter().map(BoundListener::port).collect()
    }

    pub(crate) fn run(&mut self) -> Result<(), ProxyError> {
        loop {
            self.poll_once(EVENT_POLL_INTERVAL)?;
        }
    }

    fn poll_once(&mut self, timeout: Duration) -> Result<(), ProxyError> {
        let timeout = Timespec::try_from(timeout).map_err(|_| ProxyError::Runtime)?;
        let mut storage = [MaybeUninit::<epoll::Event>::uninit(); MAX_EPOLL_EVENTS];
        let events = match epoll::wait(&self.poller, &mut storage, Some(&timeout)) {
            Ok((events, _)) => events,
            Err(rustix::io::Errno::INTR) => return Ok(()),
            Err(_) => return Err(ProxyError::Runtime),
        };

        for event in events.iter().copied() {
            let token = event.data.u64();
            let flags = event.flags;
            if token & ASSOCIATION_TOKEN_FLAG != 0 {
                self.handle_udp_response(token);
            } else {
                let index = usize::try_from(token).map_err(|_| ProxyError::Runtime)?;
                if index >= self.listeners.len()
                    || flags.intersects(epoll::EventFlags::ERR | epoll::EventFlags::HUP)
                {
                    return Err(ProxyError::Runtime);
                }
                match self.listeners.get(index) {
                    Some(BoundListener::Tcp { .. }) => self.handle_tcp_listener(index)?,
                    Some(BoundListener::Udp { .. }) => self.handle_udp_listener(index)?,
                    None => return Err(ProxyError::Runtime),
                }
            }
        }
        self.expire_udp_associations(Instant::now());
        Ok(())
    }

    fn handle_tcp_listener(&self, index: usize) -> Result<(), ProxyError> {
        let Some(BoundListener::Tcp { socket, target }) = self.listeners.get(index) else {
            return Err(ProxyError::Runtime);
        };
        for _ in 0..MAX_ACCEPTS_PER_EVENT {
            match socket.accept() {
                Ok((client, address)) => {
                    if !is_loopback_client(address) {
                        continue;
                    }
                    let Some(permit) = self.tcp_sessions.try_acquire() else {
                        continue;
                    };
                    spawn_tcp_session(client, *target, permit);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(_) => return Err(ProxyError::Runtime),
            }
        }
        Ok(())
    }

    fn handle_udp_listener(&mut self, index: usize) -> Result<(), ProxyError> {
        let mut datagram = std::mem::take(&mut self.udp_datagram);
        let result = self.handle_udp_listener_with_buffer(index, &mut datagram);
        self.udp_datagram = datagram;
        result
    }

    fn handle_udp_listener_with_buffer(
        &mut self,
        index: usize,
        datagram: &mut [u8],
    ) -> Result<(), ProxyError> {
        for _ in 0..MAX_DATAGRAMS_PER_EVENT {
            let received = {
                let Some(BoundListener::Udp { socket, .. }) = self.listeners.get(index) else {
                    return Err(ProxyError::Runtime);
                };
                socket.recv_from(datagram)
            };
            match received {
                Ok((length, SocketAddr::V4(client))) if client.ip().is_loopback() => {
                    self.forward_udp_datagram(index, client, &datagram[..length])?;
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(_) => return Err(ProxyError::Runtime),
            }
        }
        Ok(())
    }

    fn forward_udp_datagram(
        &mut self,
        listener_index: usize,
        client: SocketAddrV4,
        datagram: &[u8],
    ) -> Result<(), ProxyError> {
        let key = AssociationKey {
            listener_index,
            client,
        };
        let now = Instant::now();
        if let Some(association) = self.udp_associations.get_mut(&key) {
            if now.duration_since(association.last_client_activity) < self.udp_association_idle {
                association.last_client_activity = now;
                if !send_udp(&association.socket, datagram) {
                    let token = association.token;
                    self.remove_udp_association(token);
                }
                return Ok(());
            }
            let token = association.token;
            self.remove_udp_association(token);
        }

        if self.udp_associations.len() >= self.udp_association_limit {
            self.expire_udp_associations(now);
        }
        if self.udp_associations.len() >= self.udp_association_limit {
            return Ok(());
        }

        let target = match self.listeners.get(listener_index) {
            Some(BoundListener::Udp { target, .. }) => *target,
            _ => return Err(ProxyError::Runtime),
        };
        let Ok(socket) =
            UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)))
        else {
            return Ok(());
        };
        if socket.connect(SocketAddr::V4(target)).is_err() || socket.set_nonblocking(true).is_err()
        {
            return Ok(());
        }

        let token = self.allocate_udp_token()?;
        if epoll::add(
            &self.poller,
            &socket,
            epoll::EventData::new_u64(token),
            epoll::EventFlags::IN,
        )
        .is_err()
        {
            return Ok(());
        }
        self.udp_tokens.insert(token, key);
        self.udp_associations.insert(
            key,
            UdpAssociation {
                socket,
                token,
                last_client_activity: now,
            },
        );

        let sent = self
            .udp_associations
            .get(&key)
            .is_some_and(|association| send_udp(&association.socket, datagram));
        if !sent {
            self.remove_udp_association(token);
        }
        Ok(())
    }

    fn handle_udp_response(&mut self, token: u64) {
        let mut datagram = std::mem::take(&mut self.udp_datagram);
        self.handle_udp_response_with_buffer(token, &mut datagram);
        self.udp_datagram = datagram;
    }

    fn handle_udp_response_with_buffer(&mut self, token: u64, datagram: &mut [u8]) {
        let Some(key) = self.udp_tokens.get(&token).copied() else {
            return;
        };
        for _ in 0..MAX_DATAGRAMS_PER_EVENT {
            let received = match self.udp_associations.get(&key) {
                Some(association) => association.socket.recv(datagram),
                None => return,
            };
            match received {
                Ok(length) => {
                    let sent = match self.listeners.get(key.listener_index) {
                        Some(BoundListener::Udp { socket, .. }) => socket
                            .send_to(&datagram[..length], SocketAddr::V4(key.client))
                            .is_ok(),
                        _ => false,
                    };
                    if !sent {
                        self.remove_udp_association(token);
                        return;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return,
                Err(_) => {
                    self.remove_udp_association(token);
                    return;
                }
            }
        }
    }

    fn allocate_udp_token(&mut self) -> Result<u64, ProxyError> {
        if self.next_udp_token >= ASSOCIATION_TOKEN_FLAG {
            return Err(ProxyError::Runtime);
        }
        let token = ASSOCIATION_TOKEN_FLAG | self.next_udp_token;
        self.next_udp_token = self
            .next_udp_token
            .checked_add(1)
            .ok_or(ProxyError::Runtime)?;
        Ok(token)
    }

    fn expire_udp_associations(&mut self, now: Instant) {
        let expired = self
            .udp_associations
            .values()
            .filter_map(|association| {
                (now.duration_since(association.last_client_activity) >= self.udp_association_idle)
                    .then_some(association.token)
            })
            .collect::<Vec<_>>();
        for token in expired {
            self.remove_udp_association(token);
        }
    }

    fn remove_udp_association(&mut self, token: u64) {
        let Some(key) = self.udp_tokens.remove(&token) else {
            return;
        };
        if let Some(association) = self.udp_associations.remove(&key) {
            let _ = epoll::delete(&self.poller, &association.socket);
        }
    }
}

fn bind_all(mappings: &[Mapping]) -> Result<Vec<BoundListener>, ProxyError> {
    let mut listeners = (0..mappings.len()).map(|_| None).collect::<Vec<_>>();
    for index in binding_order(mappings) {
        let mapping = &mappings[index];
        let address = SocketAddr::V4(SocketAddrV4::new(LOOPBACK, mapping.listen_port()));
        let listener = match mapping.transport() {
            Transport::Tcp => {
                let socket = TcpListener::bind(address).map_err(|_| ProxyError::Bind)?;
                socket.set_nonblocking(true).map_err(|_| ProxyError::Bind)?;
                BoundListener::Tcp {
                    socket,
                    target: mapping.target(),
                }
            }
            Transport::Udp => {
                let socket = UdpSocket::bind(address).map_err(|_| ProxyError::Bind)?;
                socket.set_nonblocking(true).map_err(|_| ProxyError::Bind)?;
                BoundListener::Udp {
                    socket,
                    target: mapping.target(),
                }
            }
        };
        let _ = listener.port()?;
        listeners[index] = Some(listener);
    }
    listeners
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or(ProxyError::Bind)
}

fn binding_order(mappings: &[Mapping]) -> impl Iterator<Item = usize> + '_ {
    mappings
        .iter()
        .enumerate()
        .filter_map(|(index, mapping)| (mapping.listen_port() != 0).then_some(index))
        .chain(
            mappings
                .iter()
                .enumerate()
                .filter_map(|(index, mapping)| (mapping.listen_port() == 0).then_some(index)),
        )
}

fn is_loopback_client(address: SocketAddr) -> bool {
    matches!(address, SocketAddr::V4(address) if address.ip().is_loopback())
}

fn spawn_tcp_session(client: TcpStream, target: SocketAddrV4, permit: SlotPermit) {
    let session = move || relay_tcp_session(client, target, permit);
    let _ = thread::Builder::new()
        .name("service-proxy-tcp".to_owned())
        .stack_size(RELAY_THREAD_STACK_BYTES)
        .spawn(session);
}

fn relay_tcp_session(client: TcpStream, target: SocketAddrV4, _permit: SlotPermit) {
    let Ok(upstream) = TcpStream::connect_timeout(&SocketAddr::V4(target), TCP_CONNECT_TIMEOUT)
    else {
        return;
    };
    relay_connected_streams(client, upstream);
}

fn relay_connected_streams(client: TcpStream, upstream: TcpStream) {
    relay_connected_streams_with_drain_timeout(client, upstream, TCP_HALF_CLOSE_DRAIN_TIMEOUT);
}

fn relay_connected_streams_with_drain_timeout(
    client: TcpStream,
    upstream: TcpStream,
    drain_timeout: Duration,
) {
    let client = Arc::new(client);
    let upstream = Arc::new(upstream);
    let (finished, wait_for_pumps) = mpsc::channel();
    let Ok(client_to_upstream) = spawn_tcp_pump(
        "service-proxy-client-pump",
        Arc::clone(&client),
        Arc::clone(&upstream),
        finished.clone(),
    ) else {
        return;
    };
    let upstream_to_client = spawn_tcp_pump(
        "service-proxy-upstream-pump",
        Arc::clone(&upstream),
        Arc::clone(&client),
        finished.clone(),
    );
    drop(finished);
    let Ok(upstream_to_client) = upstream_to_client else {
        let _ = client.shutdown(Shutdown::Both);
        let _ = upstream.shutdown(Shutdown::Both);
        let _ = client_to_upstream.join();
        return;
    };

    if wait_for_pumps.recv().is_ok() && wait_for_pumps.recv_timeout(drain_timeout).is_err() {
        let _ = client.shutdown(Shutdown::Both);
        let _ = upstream.shutdown(Shutdown::Both);
    }
    let _ = client_to_upstream.join();
    let _ = upstream_to_client.join();
}

fn spawn_tcp_pump(
    name: &str,
    source: Arc<TcpStream>,
    destination: Arc<TcpStream>,
    finished: mpsc::Sender<()>,
) -> io::Result<thread::JoinHandle<()>> {
    thread::Builder::new()
        .name(name.to_owned())
        .stack_size(RELAY_THREAD_STACK_BYTES)
        .spawn(move || {
            let mut source = &*source;
            let mut destination = &*destination;
            let _ = io::copy(&mut source, &mut destination);
            let _ = destination.shutdown(Shutdown::Write);
            let _ = finished.send(());
        })
}

fn send_udp(socket: &UdpSocket, datagram: &[u8]) -> bool {
    match socket.send(datagram) {
        Ok(sent) => sent == datagram.len(),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => true,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn ipv4(address: SocketAddr) -> SocketAddrV4 {
        match address {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => panic!("expected IPv4"),
        }
    }

    fn accept_before(listener: &TcpListener, timeout: Duration) -> TcpStream {
        let deadline = Instant::now() + timeout;
        loop {
            match listener.accept() {
                Ok((stream, _)) => return stream,
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("backend accept failed: {error}"),
            }
        }
    }

    fn wait_for_session_count(limiter: &SlotLimiter, expected: usize) {
        let deadline = Instant::now() + Duration::from_secs(1);
        while limiter.in_use() != expected {
            assert!(
                Instant::now() < deadline,
                "session count remained {} instead of {expected}",
                limiter.in_use()
            );
            thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn later_bind_failure_rolls_back_every_earlier_listener() {
        let reservation = TcpListener::bind((LOOPBACK, 0)).expect("reserve port");
        let port = reservation.local_addr().expect("local address").port();
        drop(reservation);
        let target = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 80);
        let mappings = [
            Mapping::new(Transport::Tcp, target, port),
            Mapping::new(Transport::Tcp, target, port),
        ];

        assert!(matches!(bind_all(&mappings), Err(ProxyError::Bind)));
        TcpListener::bind((LOOPBACK, port)).expect("first listener was rolled back");
    }

    #[test]
    fn explicit_ports_are_reserved_before_dynamic_ports_without_reordering_status() {
        let target = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 80);
        let mappings = [
            Mapping::new(Transport::Tcp, target, 0),
            Mapping::new(Transport::Udp, target, 53),
            Mapping::new(Transport::Tcp, target, 54_321),
            Mapping::new(Transport::Udp, target, 0),
        ];
        assert_eq!(binding_order(&mappings).collect::<Vec<_>>(), [1, 2, 0, 3]);
    }

    #[test]
    fn delayed_tcp_response_survives_client_write_half_close() {
        let upstream_listener = TcpListener::bind((LOOPBACK, 0)).expect("upstream listener");
        let upstream_address = upstream_listener.local_addr().expect("upstream address");
        let upstream = thread::spawn(move || {
            let (mut stream, _) = upstream_listener.accept().expect("upstream accept");
            let mut request = Vec::new();
            stream.read_to_end(&mut request).expect("read request EOF");
            assert_eq!(request, b"request");
            thread::sleep(Duration::from_millis(75));
            stream.write_all(b"response").expect("write response");
            stream.shutdown(Shutdown::Write).expect("response EOF");
        });

        let front = TcpListener::bind((LOOPBACK, 0)).expect("front listener");
        let front_address = front.local_addr().expect("front address");
        let mut client = TcpStream::connect(front_address).expect("connect front");
        let (proxy_client, _) = front.accept().expect("accept front");
        let proxy_upstream = TcpStream::connect(upstream_address).expect("connect upstream");
        let relay = thread::spawn(move || {
            relay_connected_streams_with_drain_timeout(
                proxy_client,
                proxy_upstream,
                Duration::from_millis(200),
            );
        });

        client.write_all(b"request").expect("write request");
        client.shutdown(Shutdown::Write).expect("request EOF");
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .expect("read response EOF");
        assert_eq!(response, b"response");

        relay.join().expect("relay thread");
        upstream.join().expect("upstream thread");
    }

    #[test]
    fn upstream_eof_releases_session_permit_with_an_open_client_write_half() {
        let upstream_listener = TcpListener::bind((LOOPBACK, 0)).expect("upstream listener");
        let upstream_address = upstream_listener.local_addr().expect("upstream address");
        let front = TcpListener::bind((LOOPBACK, 0)).expect("front listener");
        let front_address = front.local_addr().expect("front address");
        let client = TcpStream::connect(front_address).expect("connect front");
        let (proxy_client, _) = front.accept().expect("accept front");
        let proxy_upstream = TcpStream::connect(upstream_address).expect("connect upstream");
        let (upstream, _) = upstream_listener.accept().expect("accept upstream");
        let limiter = Arc::new(SlotLimiter::new(1));
        let permit = limiter.try_acquire().expect("session permit");
        assert_eq!(limiter.in_use(), 1);
        let (relay_finished, wait_for_relay) = mpsc::channel();
        let relay = thread::spawn(move || {
            relay_connected_streams_with_drain_timeout(
                proxy_client,
                proxy_upstream,
                Duration::from_millis(50),
            );
            drop(permit);
            relay_finished.send(()).expect("report relay completion");
        });

        upstream
            .shutdown(Shutdown::Write)
            .expect("upstream response EOF");
        wait_for_relay
            .recv_timeout(Duration::from_secs(1))
            .expect("upstream EOF must release the client pump after the drain bound");

        relay.join().expect("relay thread");
        assert_eq!(limiter.in_use(), 0);
        drop(limiter.try_acquire().expect("replacement session permit"));
        drop(upstream);
        drop(client);
    }

    #[test]
    fn client_eof_releases_session_permit_when_upstream_stays_silent() {
        let upstream_listener = TcpListener::bind((LOOPBACK, 0)).expect("upstream listener");
        let upstream_address = upstream_listener.local_addr().expect("upstream address");
        let (request_received, wait_for_request) = mpsc::channel();
        let (release_upstream, wait_for_release) = mpsc::channel();
        let upstream = thread::spawn(move || {
            let (mut stream, _) = upstream_listener.accept().expect("upstream accept");
            let mut request = Vec::new();
            stream.read_to_end(&mut request).expect("read request EOF");
            assert_eq!(request, b"request");
            request_received.send(()).expect("report request EOF");
            wait_for_release.recv().expect("release silent upstream");
        });

        let front = TcpListener::bind((LOOPBACK, 0)).expect("front listener");
        let front_address = front.local_addr().expect("front address");
        let mut client = TcpStream::connect(front_address).expect("connect front");
        let (proxy_client, _) = front.accept().expect("accept front");
        let proxy_upstream = TcpStream::connect(upstream_address).expect("connect upstream");
        let limiter = Arc::new(SlotLimiter::new(1));
        let permit = limiter.try_acquire().expect("session permit");
        let (relay_finished, wait_for_relay) = mpsc::channel();
        let relay = thread::spawn(move || {
            relay_connected_streams_with_drain_timeout(
                proxy_client,
                proxy_upstream,
                Duration::from_millis(50),
            );
            drop(permit);
            relay_finished.send(()).expect("report relay completion");
        });

        client.write_all(b"request").expect("write request");
        client.shutdown(Shutdown::Write).expect("request EOF");
        wait_for_request
            .recv_timeout(Duration::from_secs(1))
            .expect("upstream observes request EOF");
        wait_for_relay
            .recv_timeout(Duration::from_secs(1))
            .expect("client EOF must release the silent upstream after the drain bound");

        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .expect("proxy response EOF");
        assert!(response.is_empty());
        assert_eq!(limiter.in_use(), 0);
        drop(limiter.try_acquire().expect("replacement session permit"));
        release_upstream.send(()).expect("release upstream");
        relay.join().expect("relay thread");
        upstream.join().expect("upstream thread");
    }

    #[test]
    fn tcp_session_contention_rejects_overload_and_reuses_the_released_slot() {
        let backend = TcpListener::bind((LOOPBACK, 0)).expect("backend listener");
        backend.set_nonblocking(true).expect("nonblocking backend");
        let target = ipv4(backend.local_addr().expect("backend address"));
        let mapping = Mapping::new(Transport::Tcp, target, 0);
        let mut proxy =
            PreparedProxy::prepare_with_limits(&[mapping], 1, 1, Duration::from_secs(30))
                .expect("prepare proxy");
        let front = SocketAddrV4::new(LOOPBACK, proxy.ports().expect("ports")[0]);

        let first = TcpStream::connect(front).expect("first client");
        proxy
            .poll_once(Duration::from_millis(100))
            .expect("admit first session");
        assert_eq!(proxy.tcp_sessions.in_use(), 1);
        let first_upstream = accept_before(&backend, Duration::from_secs(1));

        let mut overloaded = TcpStream::connect(front).expect("overloaded client");
        overloaded
            .set_read_timeout(Some(Duration::from_millis(250)))
            .expect("overloaded client timeout");
        proxy
            .poll_once(Duration::from_millis(100))
            .expect("reject overloaded session");
        assert_eq!(proxy.tcp_sessions.in_use(), 1);
        let mut byte = [0_u8; 1];
        match overloaded.read(&mut byte) {
            Ok(0) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                ) => {}
            Ok(length) => {
                panic!("over-capacity connection received {length} bytes instead of being closed")
            }
            Err(error) => panic!("over-capacity connection did not close promptly: {error}"),
        }
        assert!(
            matches!(backend.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
        );

        first.shutdown(Shutdown::Both).expect("close first client");
        first_upstream
            .shutdown(Shutdown::Both)
            .expect("close first upstream");
        wait_for_session_count(&proxy.tcp_sessions, 0);

        let replacement = TcpStream::connect(front).expect("replacement client");
        proxy
            .poll_once(Duration::from_millis(100))
            .expect("admit replacement session");
        assert_eq!(proxy.tcp_sessions.in_use(), 1);
        let replacement_upstream = accept_before(&backend, Duration::from_secs(1));
        replacement
            .shutdown(Shutdown::Both)
            .expect("close replacement client");
        replacement_upstream
            .shutdown(Shutdown::Both)
            .expect("close replacement upstream");
        wait_for_session_count(&proxy.tcp_sessions, 0);
    }

    #[test]
    fn udp_association_table_is_hard_capped_and_idle_entries_expire() {
        let backend = UdpSocket::bind((LOOPBACK, 0)).expect("backend");
        backend
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("backend timeout");
        let target = ipv4(backend.local_addr().expect("backend address"));
        let mapping = Mapping::new(Transport::Udp, target, 0);
        let mut proxy =
            PreparedProxy::prepare_with_limits(&[mapping], 1, 1, Duration::from_millis(200))
                .expect("prepare proxy");
        let receive_storage = proxy.udp_datagram.as_ptr();
        let front = SocketAddrV4::new(LOOPBACK, proxy.ports().expect("ports")[0]);
        let first = UdpSocket::bind((LOOPBACK, 0)).expect("first client");
        let second = UdpSocket::bind((LOOPBACK, 0)).expect("second client");
        first
            .set_read_timeout(Some(Duration::from_millis(100)))
            .expect("first client timeout");
        second
            .set_nonblocking(true)
            .expect("second client nonblocking");

        first.send_to(b"one", front).expect("first datagram");
        proxy
            .poll_once(Duration::from_millis(100))
            .expect("route first");
        let mut buffer = [0_u8; 16];
        let (length, proxy_source) = backend.recv_from(&mut buffer).expect("first forwarded");
        assert_eq!(&buffer[..length], b"one");
        assert_eq!(proxy.udp_associations.len(), 1);
        assert_eq!(proxy.udp_tokens.len(), 1);
        backend
            .send_to(b"reply-one", proxy_source)
            .expect("backend response");
        proxy
            .poll_once(Duration::from_millis(100))
            .expect("route backend response");
        let (length, _) = first.recv_from(&mut buffer).expect("first client response");
        assert_eq!(&buffer[..length], b"reply-one");
        assert!(second.recv_from(&mut buffer).is_err());

        second.send_to(b"two", front).expect("second datagram");
        proxy
            .poll_once(Duration::from_millis(100))
            .expect("drop over-capacity client");
        assert!(backend.recv_from(&mut buffer).is_err());
        assert_eq!(proxy.udp_associations.len(), 1);

        let expired_at = Instant::now()
            .checked_sub(proxy.udp_association_idle)
            .expect("representable expired activity");
        proxy
            .udp_associations
            .values_mut()
            .for_each(|association| association.last_client_activity = expired_at);
        proxy.poll_once(Duration::ZERO).expect("expire idle entry");
        assert!(proxy.udp_associations.is_empty());
        assert!(proxy.udp_tokens.is_empty());

        second
            .send_to(b"two", front)
            .expect("retry second datagram");
        proxy
            .poll_once(Duration::from_millis(100))
            .expect("route after expiry");
        let (length, _) = backend
            .recv_from(&mut buffer)
            .expect("second forwarded after expiry");
        assert_eq!(&buffer[..length], b"two");
        assert_eq!(
            proxy.udp_datagram.as_ptr(),
            receive_storage,
            "UDP listener and association events reuse one bounded allocation"
        );
    }

    #[test]
    fn udp_association_reuses_identity_refreshes_activity_and_rejects_stale_tokens() {
        let backend = UdpSocket::bind((LOOPBACK, 0)).expect("backend");
        backend
            .set_read_timeout(Some(Duration::from_millis(250)))
            .expect("backend timeout");
        let target = ipv4(backend.local_addr().expect("backend address"));
        let mut proxy = PreparedProxy::prepare_with_limits(
            &[Mapping::new(Transport::Udp, target, 0)],
            1,
            2,
            Duration::from_secs(30),
        )
        .expect("prepare proxy");
        let front = SocketAddrV4::new(LOOPBACK, proxy.ports().expect("ports")[0]);
        let client = UdpSocket::bind((LOOPBACK, 0)).expect("client");
        client
            .set_read_timeout(Some(Duration::from_millis(250)))
            .expect("client timeout");
        let client_address = ipv4(client.local_addr().expect("client address"));
        let key = AssociationKey {
            listener_index: 0,
            client: client_address,
        };
        let mut datagram = [0_u8; 32];

        client.send_to(b"first", front).expect("first request");
        proxy
            .poll_once(Duration::from_millis(100))
            .expect("route first request");
        let (length, first_source) = backend.recv_from(&mut datagram).expect("first forwarded");
        assert_eq!(&datagram[..length], b"first");
        let first_token = proxy
            .udp_associations
            .get(&key)
            .expect("first association")
            .token;

        let old_activity = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .expect("representable earlier activity");
        proxy
            .udp_associations
            .get_mut(&key)
            .expect("first association")
            .last_client_activity = old_activity;
        client.send_to(b"second", front).expect("second request");
        proxy
            .poll_once(Duration::from_millis(100))
            .expect("route second request");
        let (length, second_source) = backend.recv_from(&mut datagram).expect("second forwarded");
        assert_eq!(&datagram[..length], b"second");
        assert_eq!(
            second_source, first_source,
            "one client reuses one upstream socket"
        );
        let association = proxy
            .udp_associations
            .get(&key)
            .expect("reused association");
        assert_eq!(association.token, first_token);
        assert!(association.last_client_activity > old_activity);

        backend
            .send_to(b"second-response", second_source)
            .expect("backend response");
        proxy
            .poll_once(Duration::from_millis(100))
            .expect("route backend response");
        let (length, source) = client.recv_from(&mut datagram).expect("client response");
        assert_eq!(&datagram[..length], b"second-response");
        assert_eq!(source, SocketAddr::V4(front));

        let expired_at = Instant::now()
            .checked_sub(proxy.udp_association_idle)
            .expect("representable expired activity");
        proxy
            .udp_associations
            .get_mut(&key)
            .expect("association before expiry")
            .last_client_activity = expired_at;
        proxy.expire_udp_associations(Instant::now());
        assert!(proxy.udp_associations.is_empty());
        assert!(proxy.udp_tokens.is_empty());

        proxy.handle_udp_response(first_token);
        assert!(proxy.udp_associations.is_empty());
        assert!(proxy.udp_tokens.is_empty());

        client
            .send_to(b"replacement", front)
            .expect("replacement request");
        proxy
            .poll_once(Duration::from_millis(100))
            .expect("route replacement request");
        let (length, _) = backend
            .recv_from(&mut datagram)
            .expect("replacement forwarded");
        assert_eq!(&datagram[..length], b"replacement");
        let replacement_token = proxy
            .udp_associations
            .get(&key)
            .expect("replacement association")
            .token;
        assert_ne!(replacement_token, first_token);
        assert_eq!(proxy.udp_tokens.get(&replacement_token), Some(&key));
    }
}
