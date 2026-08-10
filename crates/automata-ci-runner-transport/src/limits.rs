use std::time::Duration;

use crate::ConfigurationError;

const MIB: usize = 1024 * 1024;

/// Trusted resource and time budgets for both listener and runner client.
///
/// Values are private so zero and incoherent limits cannot be constructed.
/// Builder methods consume and return the value to make startup configuration
/// straightforward without permitting mutation after sharing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportLimits {
    request_body_bytes: usize,
    response_body_bytes: usize,
    header_list_bytes: u32,
    send_buffer_bytes: usize,
    concurrent_connections: usize,
    concurrent_server_requests: usize,
    concurrent_client_requests: usize,
    concurrent_streams_per_connection: u32,
    tls_handshake_timeout: Duration,
    authentication_timeout: Duration,
    admission_timeout: Duration,
    request_body_timeout: Duration,
    handler_timeout: Duration,
    long_poll_timeout: Duration,
    graceful_shutdown_timeout: Duration,
    connection_lifetime: Duration,
    connect_timeout: Duration,
    total_request_timeout: Duration,
    response_body_timeout: Duration,
    h2_keep_alive_interval: Duration,
    h2_keep_alive_timeout: Duration,
}

impl TransportLimits {
    /// Largest request or response body supported by this transport.
    ///
    /// This matches the current protocol's complete encoded-message ceiling.
    pub const MAXIMUM_BODY_BYTES: usize = 16 * MIB;

    /// Largest accepted transport deadline or connection lifetime.
    ///
    /// Transport timers are operational bounds, not durable schedules. Keeping
    /// them within one day also guarantees that runtime deadline arithmetic is
    /// representable instead of allowing an accepted value to panic later.
    pub const MAXIMUM_TIME_LIMIT: Duration = Duration::from_hours(24);

    /// Changes the request and response body ceilings.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigurationError`] if either limit is zero or exceeds the
    /// current protocol's complete encoded-message ceiling.
    pub fn with_body_limits(
        mut self,
        request_body_bytes: usize,
        response_body_bytes: usize,
    ) -> Result<Self, ConfigurationError> {
        require_nonzero(&request_body_bytes)?;
        require_nonzero(&response_body_bytes)?;
        if request_body_bytes > Self::MAXIMUM_BODY_BYTES
            || response_body_bytes > Self::MAXIMUM_BODY_BYTES
        {
            return Err(ConfigurationError::InvalidLimit);
        }
        self.request_body_bytes = request_body_bytes;
        self.response_body_bytes = response_body_bytes;
        Ok(self)
    }

    /// Changes the HTTP/2 header, per-stream send-buffer, and stream ceilings.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigurationError`] if a value is zero or the send buffer
    /// cannot be represented by the HTTP/2 implementation.
    pub fn with_http2_limits(
        mut self,
        header_list_bytes: u32,
        send_buffer_bytes: usize,
        concurrent_streams_per_connection: u32,
    ) -> Result<Self, ConfigurationError> {
        require_nonzero(&header_list_bytes)?;
        require_nonzero(&send_buffer_bytes)?;
        require_nonzero(&concurrent_streams_per_connection)?;
        if send_buffer_bytes > u32::MAX as usize {
            return Err(ConfigurationError::InvalidLimit);
        }
        self.header_list_bytes = header_list_bytes;
        self.send_buffer_bytes = send_buffer_bytes;
        self.concurrent_streams_per_connection = concurrent_streams_per_connection;
        Ok(self)
    }

    /// Changes connection-level and request-level admission ceilings.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigurationError`] if a value is zero.
    pub fn with_concurrency_limits(
        mut self,
        concurrent_connections: usize,
        concurrent_server_requests: usize,
        concurrent_client_requests: usize,
    ) -> Result<Self, ConfigurationError> {
        require_nonzero(&concurrent_connections)?;
        require_nonzero(&concurrent_server_requests)?;
        require_nonzero(&concurrent_client_requests)?;
        self.concurrent_connections = concurrent_connections;
        self.concurrent_server_requests = concurrent_server_requests;
        self.concurrent_client_requests = concurrent_client_requests;
        Ok(self)
    }

    /// Changes TLS-handshake and application machine-authentication deadlines.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigurationError`] if a duration is zero or exceeds the
    /// common transport time ceiling.
    pub fn with_authentication_timeouts(
        mut self,
        tls_handshake_timeout: Duration,
        authentication_timeout: Duration,
    ) -> Result<Self, ConfigurationError> {
        require_duration(tls_handshake_timeout)?;
        require_duration(authentication_timeout)?;
        self.tls_handshake_timeout = tls_handshake_timeout;
        self.authentication_timeout = authentication_timeout;
        Ok(self)
    }

    /// Changes server admission, body-read, ordinary-handler, and long-poll deadlines.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigurationError`] if a duration is zero, exceeds the common
    /// transport time ceiling, or the long-poll deadline is shorter than the
    /// ordinary handler deadline.
    pub fn with_server_request_timeouts(
        mut self,
        admission_timeout: Duration,
        request_body_timeout: Duration,
        handler_timeout: Duration,
        long_poll_timeout: Duration,
    ) -> Result<Self, ConfigurationError> {
        require_duration(admission_timeout)?;
        require_duration(request_body_timeout)?;
        require_duration(handler_timeout)?;
        require_duration(long_poll_timeout)?;
        if long_poll_timeout < handler_timeout || long_poll_timeout > self.connection_lifetime {
            return Err(ConfigurationError::IncoherentLimits);
        }
        self.admission_timeout = admission_timeout;
        self.request_body_timeout = request_body_timeout;
        self.handler_timeout = handler_timeout;
        self.long_poll_timeout = long_poll_timeout;
        Ok(self)
    }

    /// Changes client connect, admission, total request, and body-read deadlines.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigurationError`] if a duration is zero, exceeds the common
    /// transport time ceiling, or a component deadline exceeds the total
    /// request deadline.
    pub fn with_client_timeouts(
        mut self,
        connect_timeout: Duration,
        admission_timeout: Duration,
        total_request_timeout: Duration,
        response_body_timeout: Duration,
    ) -> Result<Self, ConfigurationError> {
        require_duration(connect_timeout)?;
        require_duration(admission_timeout)?;
        require_duration(total_request_timeout)?;
        require_duration(response_body_timeout)?;
        if connect_timeout > total_request_timeout
            || response_body_timeout > total_request_timeout
            || admission_timeout > total_request_timeout
        {
            return Err(ConfigurationError::IncoherentLimits);
        }
        self.connect_timeout = connect_timeout;
        self.admission_timeout = admission_timeout;
        self.total_request_timeout = total_request_timeout;
        self.response_body_timeout = response_body_timeout;
        Ok(self)
    }

    /// Changes HTTP/2 ping interval and acknowledgement deadline.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigurationError`] if either duration is zero or exceeds the
    /// common transport time ceiling.
    pub fn with_keep_alive(
        mut self,
        interval: Duration,
        timeout: Duration,
    ) -> Result<Self, ConfigurationError> {
        require_duration(interval)?;
        require_duration(timeout)?;
        self.h2_keep_alive_interval = interval;
        self.h2_keep_alive_timeout = timeout;
        Ok(self)
    }

    /// Changes the maximum time allowed for graceful connection draining.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigurationError`] if the duration is zero or exceeds the
    /// common transport time ceiling.
    pub fn with_graceful_shutdown_timeout(
        mut self,
        timeout: Duration,
    ) -> Result<Self, ConfigurationError> {
        require_duration(timeout)?;
        self.graceful_shutdown_timeout = timeout;
        Ok(self)
    }

    /// Changes the maximum lifetime of one accepted HTTP/2 connection.
    ///
    /// This bounds peers that finish TLS but stall before completing request
    /// headers. Expiry starts graceful draining; replica-neutral clients can
    /// reconnect without affinity.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigurationError`] if the duration is zero, exceeds the
    /// common transport time ceiling, or is shorter than the configured
    /// long-poll deadline.
    pub fn with_connection_lifetime(
        mut self,
        lifetime: Duration,
    ) -> Result<Self, ConfigurationError> {
        require_duration(lifetime)?;
        if lifetime < self.long_poll_timeout {
            return Err(ConfigurationError::IncoherentLimits);
        }
        self.connection_lifetime = lifetime;
        Ok(self)
    }

    pub(crate) const fn request_body_bytes(self) -> usize {
        self.request_body_bytes
    }

    pub(crate) const fn response_body_bytes(self) -> usize {
        self.response_body_bytes
    }

    pub(crate) const fn header_list_bytes(self) -> u32 {
        self.header_list_bytes
    }

    pub(crate) const fn send_buffer_bytes(self) -> usize {
        self.send_buffer_bytes
    }

    pub(crate) const fn concurrent_connections(self) -> usize {
        self.concurrent_connections
    }

    pub(crate) const fn concurrent_server_requests(self) -> usize {
        self.concurrent_server_requests
    }

    pub(crate) const fn concurrent_client_requests(self) -> usize {
        self.concurrent_client_requests
    }

    pub(crate) const fn concurrent_streams_per_connection(self) -> u32 {
        self.concurrent_streams_per_connection
    }

    pub(crate) const fn tls_handshake_timeout(self) -> Duration {
        self.tls_handshake_timeout
    }

    pub(crate) const fn authentication_timeout(self) -> Duration {
        self.authentication_timeout
    }

    pub(crate) const fn admission_timeout(self) -> Duration {
        self.admission_timeout
    }

    pub(crate) const fn request_body_timeout(self) -> Duration {
        self.request_body_timeout
    }

    pub(crate) const fn handler_timeout(self) -> Duration {
        self.handler_timeout
    }

    pub(crate) const fn long_poll_timeout(self) -> Duration {
        self.long_poll_timeout
    }

    pub(crate) const fn graceful_shutdown_timeout(self) -> Duration {
        self.graceful_shutdown_timeout
    }

    pub(crate) const fn connection_lifetime(self) -> Duration {
        self.connection_lifetime
    }

    pub(crate) const fn connect_timeout(self) -> Duration {
        self.connect_timeout
    }

    pub(crate) const fn total_request_timeout(self) -> Duration {
        self.total_request_timeout
    }

    pub(crate) const fn response_body_timeout(self) -> Duration {
        self.response_body_timeout
    }

    pub(crate) const fn h2_keep_alive_interval(self) -> Duration {
        self.h2_keep_alive_interval
    }

    pub(crate) const fn h2_keep_alive_timeout(self) -> Duration {
        self.h2_keep_alive_timeout
    }
}

impl Default for TransportLimits {
    fn default() -> Self {
        Self {
            request_body_bytes: Self::MAXIMUM_BODY_BYTES,
            response_body_bytes: Self::MAXIMUM_BODY_BYTES,
            header_list_bytes: 16 * 1024,
            send_buffer_bytes: 256 * 1024,
            concurrent_connections: 1_024,
            concurrent_server_requests: 256,
            concurrent_client_requests: 64,
            concurrent_streams_per_connection: 64,
            tls_handshake_timeout: Duration::from_secs(10),
            authentication_timeout: Duration::from_secs(5),
            admission_timeout: Duration::from_secs(1),
            request_body_timeout: Duration::from_secs(15),
            handler_timeout: Duration::from_secs(30),
            long_poll_timeout: Duration::from_secs(65),
            graceful_shutdown_timeout: Duration::from_secs(10),
            connection_lifetime: Duration::from_mins(10),
            connect_timeout: Duration::from_secs(10),
            total_request_timeout: Duration::from_secs(75),
            response_body_timeout: Duration::from_secs(15),
            h2_keep_alive_interval: Duration::from_secs(30),
            h2_keep_alive_timeout: Duration::from_secs(10),
        }
    }
}

fn require_nonzero<T>(value: &T) -> Result<(), ConfigurationError>
where
    T: Default + PartialEq,
{
    if *value == T::default() {
        Err(ConfigurationError::InvalidLimit)
    } else {
        Ok(())
    }
}

fn require_duration(value: Duration) -> Result<(), ConfigurationError> {
    if value.is_zero() || value > TransportLimits::MAXIMUM_TIME_LIMIT {
        Err(ConfigurationError::InvalidLimit)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::TransportLimits;
    use crate::ConfigurationError;

    #[test]
    fn body_limits_reject_zero_and_values_above_the_protocol_ceiling() {
        assert!(TransportLimits::default().with_body_limits(1, 1).is_ok());
        assert!(
            TransportLimits::default()
                .with_body_limits(
                    TransportLimits::MAXIMUM_BODY_BYTES,
                    TransportLimits::MAXIMUM_BODY_BYTES,
                )
                .is_ok()
        );
        assert!(
            TransportLimits::default()
                .with_body_limits(0, TransportLimits::MAXIMUM_BODY_BYTES)
                .is_err()
        );
        assert!(
            TransportLimits::default()
                .with_body_limits(
                    TransportLimits::MAXIMUM_BODY_BYTES,
                    TransportLimits::MAXIMUM_BODY_BYTES + 1,
                )
                .is_err()
        );
    }

    #[test]
    fn time_limits_accept_the_exact_ceiling_and_reject_one_over_every_builder() {
        let maximum = TransportLimits::MAXIMUM_TIME_LIMIT;
        let one_over = maximum
            .checked_add(Duration::from_nanos(1))
            .expect("one nanosecond above the time ceiling");
        let exact = TransportLimits::default()
            .with_connection_lifetime(maximum)
            .and_then(|limits| limits.with_authentication_timeouts(maximum, maximum))
            .and_then(|limits| {
                limits.with_server_request_timeouts(maximum, maximum, maximum, maximum)
            })
            .and_then(|limits| limits.with_client_timeouts(maximum, maximum, maximum, maximum))
            .and_then(|limits| limits.with_keep_alive(maximum, maximum))
            .and_then(|limits| limits.with_graceful_shutdown_timeout(maximum));
        assert!(exact.is_ok());

        assert_eq!(
            TransportLimits::default().with_authentication_timeouts(one_over, maximum),
            Err(ConfigurationError::InvalidLimit)
        );
        assert_eq!(
            TransportLimits::default()
                .with_server_request_timeouts(one_over, maximum, maximum, maximum,),
            Err(ConfigurationError::InvalidLimit)
        );
        assert_eq!(
            TransportLimits::default().with_client_timeouts(one_over, maximum, maximum, maximum,),
            Err(ConfigurationError::InvalidLimit)
        );
        assert_eq!(
            TransportLimits::default().with_keep_alive(one_over, maximum),
            Err(ConfigurationError::InvalidLimit)
        );
        assert_eq!(
            TransportLimits::default().with_graceful_shutdown_timeout(one_over),
            Err(ConfigurationError::InvalidLimit)
        );
        assert_eq!(
            TransportLimits::default().with_connection_lifetime(one_over),
            Err(ConfigurationError::InvalidLimit)
        );
        assert_eq!(
            TransportLimits::default()
                .with_authentication_timeouts(Duration::ZERO, Duration::from_secs(1)),
            Err(ConfigurationError::InvalidLimit)
        );
    }
}
