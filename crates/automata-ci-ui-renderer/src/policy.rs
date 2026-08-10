use std::time::Duration;

use crate::{MAX_RENDER_REQUEST_UTF8_BYTES, MAX_RENDERED_HTML_UTF8_BYTES, PolicyError};

const KIBIBYTE: usize = 1024;
const MEBIBYTE: usize = KIBIBYTE * KIBIBYTE;

/// Immutable resource and admission limits for one renderer runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RenderPolicy {
    pub(crate) max_input_bytes: usize,
    pub(crate) max_output_bytes: usize,
    pub(crate) max_total_memory_bytes: usize,
    pub(crate) max_table_elements: usize,
    pub(crate) max_instances: usize,
    pub(crate) max_tables: usize,
    pub(crate) max_memories: usize,
    pub(crate) max_host_resources: usize,
    pub(crate) fuel: u64,
    pub(crate) timeout: Duration,
    pub(crate) epoch_tick: Duration,
    pub(crate) max_concurrent_renders: usize,
}

impl RenderPolicy {
    /// Create a builder initialized with the production default limits.
    pub fn builder() -> RenderPolicyBuilder {
        RenderPolicyBuilder::default()
    }

    /// Return the maximum serialized request size in UTF-8 bytes.
    pub fn max_input_bytes(&self) -> usize {
        self.max_input_bytes
    }

    /// Return the maximum rendered HTML size in UTF-8 bytes.
    pub fn max_output_bytes(&self) -> usize {
        self.max_output_bytes
    }

    /// Maximum aggregate linear-memory allocation across the guest store.
    pub fn max_total_memory_bytes(&self) -> usize {
        self.max_total_memory_bytes
    }

    /// Maximum number of concurrently live linear memories in the guest store.
    pub fn max_memories(&self) -> usize {
        self.max_memories
    }

    /// Return the WebAssembly instruction-fuel budget for one render.
    pub fn fuel(&self) -> u64 {
        self.fuel
    }

    /// Return the elapsed-time deadline for one render.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Return the admission limit for each render-processing stage.
    ///
    /// Validation and Wasmtime execution have independent gates of this size,
    /// so malformed input cannot consume an execution slot. At most this many
    /// requests may occupy either stage at once.
    pub fn max_concurrent_renders(&self) -> usize {
        self.max_concurrent_renders
    }

    pub(crate) fn deadline_ticks(&self) -> u64 {
        let duration = self.timeout.as_nanos();
        let tick = self.epoch_tick.as_nanos();
        let ticks = duration.saturating_add(tick.saturating_sub(1)) / tick;
        u64::try_from(ticks.max(1)).unwrap_or(u64::MAX)
    }
}

impl Default for RenderPolicy {
    fn default() -> Self {
        RenderPolicyBuilder::default()
            .build()
            .expect("the built-in renderer policy must remain valid")
    }
}

/// Builder for [`RenderPolicy`].
#[must_use]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenderPolicyBuilder {
    policy: RenderPolicy,
}

impl Default for RenderPolicyBuilder {
    fn default() -> Self {
        Self {
            policy: RenderPolicy {
                max_input_bytes: MAX_RENDER_REQUEST_UTF8_BYTES,
                max_output_bytes: MAX_RENDERED_HTML_UTF8_BYTES,
                max_total_memory_bytes: 128 * MEBIBYTE,
                max_table_elements: 32 * KIBIBYTE,
                max_instances: 128,
                max_tables: 32,
                // The generated renderer component currently needs exactly
                // one linear memory. Keep this at the proven minimum.
                max_memories: 1,
                max_host_resources: 1_024,
                fuel: 10_000_000_000,
                timeout: Duration::from_secs(2),
                epoch_tick: Duration::from_millis(10),
                max_concurrent_renders: 4,
            },
        }
    }
}

impl RenderPolicyBuilder {
    /// Set a stricter input limit, up to the shared renderer contract cap.
    pub fn max_input_bytes(mut self, value: usize) -> Self {
        self.policy.max_input_bytes = value;
        self
    }

    /// Set a stricter output limit, up to the shared renderer contract cap.
    pub fn max_output_bytes(mut self, value: usize) -> Self {
        self.policy.max_output_bytes = value;
        self
    }

    /// Set the aggregate linear-memory cap across every guest memory.
    pub fn max_total_memory_bytes(mut self, value: usize) -> Self {
        self.policy.max_total_memory_bytes = value;
        self
    }

    /// Set the maximum number of elements permitted in each guest table.
    pub fn max_table_elements(mut self, value: usize) -> Self {
        self.policy.max_table_elements = value;
        self
    }

    /// Set the maximum number of component instances in one guest store.
    pub fn max_instances(mut self, value: usize) -> Self {
        self.policy.max_instances = value;
        self
    }

    /// Set the maximum number of tables in one guest store.
    pub fn max_tables(mut self, value: usize) -> Self {
        self.policy.max_tables = value;
        self
    }

    /// Set the maximum number of linear memories in one guest store.
    pub fn max_memories(mut self, value: usize) -> Self {
        self.policy.max_memories = value;
        self
    }

    /// Set the maximum number of host resources in the WASI resource table.
    pub fn max_host_resources(mut self, value: usize) -> Self {
        self.policy.max_host_resources = value;
        self
    }

    /// Set the WebAssembly instruction-fuel budget for one render.
    pub fn fuel(mut self, value: u64) -> Self {
        self.policy.fuel = value;
        self
    }

    /// Set the elapsed-time deadline for one render.
    pub fn timeout(mut self, value: Duration) -> Self {
        self.policy.timeout = value;
        self
    }

    /// Set the engine epoch-tick interval used to enforce render deadlines.
    pub fn epoch_tick(mut self, value: Duration) -> Self {
        self.policy.epoch_tick = value;
        self
    }

    /// Set the admission limit applied independently to validation and execution.
    pub fn max_concurrent_renders(mut self, value: usize) -> Self {
        self.policy.max_concurrent_renders = value;
        self
    }

    /// Validate and create an immutable policy.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError`] if a limit is zero, a byte limit exceeds the
    /// shared renderer contract, or the output cap exceeds guest memory.
    pub fn build(self) -> Result<RenderPolicy, PolicyError> {
        for (name, value) in [
            ("max_input_bytes", self.policy.max_input_bytes),
            ("max_output_bytes", self.policy.max_output_bytes),
            ("max_total_memory_bytes", self.policy.max_total_memory_bytes),
            ("max_table_elements", self.policy.max_table_elements),
            ("max_instances", self.policy.max_instances),
            ("max_tables", self.policy.max_tables),
            ("max_memories", self.policy.max_memories),
            ("max_host_resources", self.policy.max_host_resources),
            ("max_concurrent_renders", self.policy.max_concurrent_renders),
        ] {
            if value == 0 {
                return Err(PolicyError::ZeroLimit { name });
            }
        }
        if self.policy.fuel == 0 {
            return Err(PolicyError::ZeroLimit { name: "fuel" });
        }
        if self.policy.timeout.is_zero() {
            return Err(PolicyError::ZeroLimit { name: "timeout" });
        }
        if self.policy.epoch_tick.is_zero() {
            return Err(PolicyError::ZeroLimit { name: "epoch_tick" });
        }
        if self.policy.max_input_bytes > MAX_RENDER_REQUEST_UTF8_BYTES {
            return Err(PolicyError::InputExceedsContract {
                max_bytes: MAX_RENDER_REQUEST_UTF8_BYTES,
            });
        }
        if self.policy.max_output_bytes > MAX_RENDERED_HTML_UTF8_BYTES {
            return Err(PolicyError::OutputExceedsContract {
                max_bytes: MAX_RENDERED_HTML_UTF8_BYTES,
            });
        }
        if self.policy.max_output_bytes > self.policy.max_total_memory_bytes {
            return Err(PolicyError::OutputExceedsMemory);
        }
        Ok(self.policy)
    }
}
