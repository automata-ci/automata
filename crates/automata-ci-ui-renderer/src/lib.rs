#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![doc = "An isolated React SSR runtime and its immutable client assets."]

mod assets;
mod error;
mod generated_assets {
    include!(concat!(env!("OUT_DIR"), "/generated_assets.rs"));
}
mod generated_contract {
    include!(concat!(env!("OUT_DIR"), "/generated_contract.rs"));
}
mod policy;
mod port;
mod runtime;

pub use assets::{AssetContentType, ClientAssetManifest, EmbeddedAsset, client_assets, find_asset};
pub use error::{PolicyError, RenderError, RendererInitError, ResourceLimit};
pub use generated_contract::{MAX_RENDER_REQUEST_UTF8_BYTES, MAX_RENDERED_HTML_UTF8_BYTES};
pub use policy::{RenderPolicy, RenderPolicyBuilder};
pub use port::{RenderedPage, Renderer};
pub use runtime::WasmtimeRenderer;
