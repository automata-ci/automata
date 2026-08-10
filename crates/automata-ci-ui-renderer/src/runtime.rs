use std::fmt;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{Config, Engine, ResourceLimiter, Store, StoreLimits, StoreLimitsBuilder, Trap};
use wasmtime_wasi::p2::add_to_linker_sync;
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

use crate::generated_assets::{COMPONENT_BYTES, COMPONENT_SHA256};
use crate::{RenderError, RenderPolicy, RenderedPage, Renderer, RendererInitError, ResourceLimit};

mod bindings {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "renderer",
    });
}

struct HostState {
    table: ResourceTable,
    wasi: WasiCtx,
    limits: TrackedLimits,
}

impl HostState {
    fn isolated(policy: &RenderPolicy) -> Self {
        let mut table = ResourceTable::new();
        table.set_max_capacity(policy.max_host_resources);

        let mut wasi = WasiCtxBuilder::new();
        wasi.allow_tcp(false)
            .allow_udp(false)
            .allow_ip_name_lookup(false);

        let limits = TrackedLimits::new(policy);

        Self {
            table,
            wasi: wasi.build(),
            limits,
        }
    }
}

impl WasiView for HostState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

struct Runtime {
    engine: Engine,
    component: Component,
    linker: Linker<HostState>,
    _ticker: EpochTicker,
    validation_admission: AdmissionGate,
    render_admission: AdmissionGate,
}

/// Wasmtime implementation of the renderer port.
///
/// Compiled component code is shared, but guest state is never pooled: every
/// request gets a new store, WASI context, and component instance.
#[derive(Clone)]
pub struct WasmtimeRenderer {
    runtime: Arc<Runtime>,
    policy: RenderPolicy,
}

impl fmt::Debug for WasmtimeRenderer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WasmtimeRenderer")
            .field("component_sha256", &COMPONENT_SHA256)
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl WasmtimeRenderer {
    /// Compile the embedded component and start its deadline ticker.
    ///
    /// # Errors
    ///
    /// Returns [`RendererInitError`] if the policy is invalid, Wasmtime cannot
    /// initialize, the embedded component is invalid, or restricted WASI
    /// imports cannot be linked.
    pub fn new(policy: RenderPolicy) -> Result<Self, RendererInitError> {
        // Revalidate values even if a policy is later deserialized or gains
        // another construction path.
        let policy = RenderPolicy::builder()
            .max_input_bytes(policy.max_input_bytes)
            .max_output_bytes(policy.max_output_bytes)
            .max_total_memory_bytes(policy.max_total_memory_bytes)
            .max_table_elements(policy.max_table_elements)
            .max_instances(policy.max_instances)
            .max_tables(policy.max_tables)
            .max_memories(policy.max_memories)
            .max_host_resources(policy.max_host_resources)
            .fuel(policy.fuel)
            .timeout(policy.timeout)
            .epoch_tick(policy.epoch_tick)
            .max_concurrent_renders(policy.max_concurrent_renders)
            .build()?;

        let mut config = Config::new();
        config.consume_fuel(true).epoch_interruption(true);
        let engine = Engine::new(&config).map_err(|error| RendererInitError::Engine {
            message: error.to_string(),
        })?;
        let component = Component::new(&engine, COMPONENT_BYTES).map_err(|error| {
            RendererInitError::Component {
                message: error.to_string(),
            }
        })?;

        let mut linker = Linker::new(&engine);
        add_to_linker_sync(&mut linker).map_err(|error| RendererInitError::Linker {
            message: error.to_string(),
        })?;

        let ticker = EpochTicker::start(engine.clone(), policy.epoch_tick).map_err(|error| {
            RendererInitError::Engine {
                message: error.to_string(),
            }
        })?;
        Ok(Self {
            runtime: Arc::new(Runtime {
                engine,
                component,
                linker,
                _ticker: ticker,
                validation_admission: AdmissionGate::new(policy.max_concurrent_renders),
                render_admission: AdmissionGate::new(policy.max_concurrent_renders),
            }),
            policy,
        })
    }

    /// Return the lowercase hexadecimal SHA-256 digest of the embedded component.
    pub fn component_sha256(&self) -> &'static str {
        COMPONENT_SHA256
    }

    fn render_isolated(&self, request_json: &str) -> Result<RenderedPage, RenderError> {
        if request_json.len() > self.policy.max_input_bytes {
            return Err(RenderError::InputTooLarge {
                actual_bytes: request_json.len(),
                max_bytes: self.policy.max_input_bytes,
            });
        }
        let validation_permit = self
            .runtime
            .validation_admission
            .try_acquire()
            .ok_or(RenderError::AtCapacity)?;
        if let Err(error) = serde_json::from_str::<serde_json::Value>(request_json) {
            return Err(RenderError::MalformedRequest {
                line: error.line(),
                column: error.column(),
            });
        }
        drop(validation_permit);

        let _render_permit = self
            .runtime
            .render_admission
            .try_acquire()
            .ok_or(RenderError::AtCapacity)?;

        let host = HostState::isolated(&self.policy);
        let mut store = Store::new(&self.runtime.engine, host);
        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(self.policy.fuel)
            .map_err(|error| classify_execution_error(&error))?;
        store.set_epoch_deadline(self.policy.deadline_ticks());
        store.epoch_deadline_trap();

        let renderer = bindings::Renderer::instantiate(
            &mut store,
            &self.runtime.component,
            &self.runtime.linker,
        )
        .map_err(|error| classify_store_execution_error(&store, &error))?;
        // Wasmtime charges guest-to-host component values before lifting them.
        // Capping this fuel prevents an oversized returned string from causing
        // an equally oversized host allocation. The post-lift check below is
        // retained because transcoding a non-UTF-8 canonical string can grow.
        store.set_hostcall_fuel(self.policy.max_output_bytes);
        let output = renderer
            .call_render(&mut store, request_json)
            .map_err(|error| {
                classify_render_call_error(&store, &error, self.policy.max_output_bytes)
            })?;

        if output.len() > self.policy.max_output_bytes {
            return Err(RenderError::OutputTooLarge {
                max_bytes: self.policy.max_output_bytes,
            });
        }
        Ok(RenderedPage::from_complete_html(output))
    }
}

impl Renderer for WasmtimeRenderer {
    fn render(&self, request_json: &str) -> Result<RenderedPage, RenderError> {
        self.render_isolated(request_json)
    }
}

fn classify_execution_error(error: &wasmtime::Error) -> RenderError {
    match error.downcast_ref::<Trap>() {
        Some(Trap::OutOfFuel) => RenderError::ResourceExhausted(ResourceLimit::Fuel),
        Some(Trap::Interrupt) => RenderError::ResourceExhausted(ResourceLimit::Deadline),
        Some(Trap::MemoryOutOfBounds | Trap::StackOverflow) => {
            RenderError::ResourceExhausted(ResourceLimit::Memory)
        }
        _ => RenderError::GuestExecution,
    }
}

fn classify_store_execution_error(
    store: &Store<HostState>,
    error: &wasmtime::Error,
) -> RenderError {
    store.data().limits.exhausted.map_or_else(
        || classify_execution_error(error),
        RenderError::ResourceExhausted,
    )
}

fn classify_render_call_error(
    store: &Store<HostState>,
    error: &wasmtime::Error,
    max_output_bytes: usize,
) -> RenderError {
    // Wasmtime's hostcall-fuel exhaustion type is private in 47.0.3, which is
    // pinned by the workspace. Match its stable diagnostic in the full error
    // chain so the public boundary remains typed and fail-closed.
    const HOSTCALL_FUEL_EXHAUSTED: &str = "fuel allocated for hostcalls has been exhausted";
    if error
        .chain()
        .any(|cause| cause.to_string().contains(HOSTCALL_FUEL_EXHAUSTED))
    {
        return RenderError::OutputTooLarge {
            max_bytes: max_output_bytes,
        };
    }
    classify_store_execution_error(store, error)
}

#[derive(Debug)]
struct TrackedLimits {
    inner: StoreLimits,
    exhausted: Option<ResourceLimit>,
    total_memory_bytes: usize,
    max_total_memory_bytes: usize,
}

impl TrackedLimits {
    fn new(policy: &RenderPolicy) -> Self {
        Self {
            inner: StoreLimitsBuilder::new()
                // This remains a per-memory backstop. `memory_growing` below
                // additionally accounts for all memories in aggregate.
                .memory_size(policy.max_total_memory_bytes)
                .table_elements(policy.max_table_elements)
                .instances(policy.max_instances)
                .tables(policy.max_tables)
                .memories(policy.max_memories)
                .trap_on_grow_failure(true)
                .build(),
            exhausted: None,
            total_memory_bytes: 0,
            max_total_memory_bytes: policy.max_total_memory_bytes,
        }
    }

    fn record<T>(
        &mut self,
        limit: ResourceLimit,
        result: wasmtime::Result<T>,
        accepted: impl FnOnce(&T) -> bool,
    ) -> wasmtime::Result<T> {
        let exhausted = match result.as_ref() {
            Ok(value) => !accepted(value),
            Err(_) => true,
        };
        if exhausted {
            self.exhausted = Some(limit);
        }
        result
    }
}

impl ResourceLimiter for TrackedLimits {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        let Some(additional_bytes) = desired.checked_sub(current) else {
            self.exhausted = Some(ResourceLimit::Memory);
            return Err(wasmtime::Error::msg(
                "guest memory size decreased during a growth request",
            ));
        };
        let Some(total_memory_bytes) = self.total_memory_bytes.checked_add(additional_bytes) else {
            self.exhausted = Some(ResourceLimit::Memory);
            return Err(wasmtime::Error::msg(
                "aggregate WebAssembly memory accounting overflowed",
            ));
        };
        if total_memory_bytes > self.max_total_memory_bytes {
            self.exhausted = Some(ResourceLimit::Memory);
            return Err(wasmtime::Error::msg(
                "aggregate WebAssembly memory limit exceeded",
            ));
        }

        let result = self.inner.memory_growing(current, desired, maximum);
        let result = self.record(ResourceLimit::Memory, result, |allowed| *allowed);
        if matches!(result, Ok(true)) {
            // ResourceLimiter has no deallocation callback. Store memory is
            // therefore accounted monotonically, which is conservative if a
            // component ever creates and discards memories within one render.
            self.total_memory_bytes = total_memory_bytes;
        }
        result
    }

    fn memory_grow_failed(&mut self, error: wasmtime::Error) -> wasmtime::Result<()> {
        let result = self.inner.memory_grow_failed(error);
        self.record(ResourceLimit::Memory, result, |()| false)
    }

    fn table_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        let result = self.inner.table_growing(current, desired, maximum);
        self.record(ResourceLimit::Table, result, |allowed| *allowed)
    }

    fn table_grow_failed(&mut self, error: wasmtime::Error) -> wasmtime::Result<()> {
        let result = self.inner.table_grow_failed(error);
        self.record(ResourceLimit::Table, result, |()| false)
    }

    fn instances(&self) -> usize {
        self.inner.instances()
    }

    fn tables(&self) -> usize {
        self.inner.tables()
    }

    fn memories(&self) -> usize {
        self.inner.memories()
    }
}

#[derive(Debug)]
struct AdmissionGate {
    available: Mutex<usize>,
}

impl AdmissionGate {
    fn new(capacity: usize) -> Self {
        Self {
            available: Mutex::new(capacity),
        }
    }

    fn try_acquire(&self) -> Option<AdmissionPermit<'_>> {
        let mut available = self
            .available
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *available == 0 {
            return None;
        }
        *available -= 1;
        Some(AdmissionPermit { gate: self })
    }

    fn release(&self) {
        let mut available = self
            .available
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *available += 1;
    }
}

#[derive(Debug)]
struct AdmissionPermit<'a> {
    gate: &'a AdmissionGate,
}

impl Drop for AdmissionPermit<'_> {
    fn drop(&mut self) {
        self.gate.release();
    }
}

#[cfg(test)]
mod admission_tests {
    use super::*;

    #[test]
    fn validation_is_bounded_separately_from_wasmtime_admission() {
        let renderer = WasmtimeRenderer::new(
            RenderPolicy::builder()
                .max_concurrent_renders(1)
                .build()
                .expect("valid policy"),
        )
        .expect("renderer initializes");

        let render_permit = renderer
            .runtime
            .render_admission
            .try_acquire()
            .expect("reserve the Wasmtime slot");
        assert!(matches!(
            renderer.render("{not-json"),
            Err(RenderError::MalformedRequest { .. })
        ));
        drop(render_permit);

        let _validation_permit = renderer
            .runtime
            .validation_admission
            .try_acquire()
            .expect("reserve the validation slot");
        assert_eq!(renderer.render("{not-json"), Err(RenderError::AtCapacity));
    }
}

#[derive(Debug)]
struct EpochTicker {
    state: Arc<(Mutex<bool>, Condvar)>,
    worker: Option<JoinHandle<()>>,
}

impl EpochTicker {
    fn start(engine: Engine, interval: Duration) -> std::io::Result<Self> {
        let state = Arc::new((Mutex::new(false), Condvar::new()));
        let thread_state = Arc::clone(&state);
        let worker = thread::Builder::new()
            .name("automata-ui-epoch".to_owned())
            .spawn(move || tick_epochs(&engine, &thread_state, interval))?;
        Ok(Self {
            state,
            worker: Some(worker),
        })
    }
}

impl Drop for EpochTicker {
    fn drop(&mut self) {
        let (lock, wake) = &*self.state;
        *lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        wake.notify_all();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn tick_epochs(engine: &Engine, state: &(Mutex<bool>, Condvar), interval: Duration) {
    let (lock, wake) = state;
    let mut stopped = lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    loop {
        let (next_stopped, wait) = wake
            .wait_timeout(stopped, interval)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        stopped = next_stopped;
        if *stopped {
            break;
        }
        if wait.timed_out() {
            engine.increment_epoch();
        }
    }
}
