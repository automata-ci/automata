use crate::generated_assets::{
    CLIENT_SCRIPT_BYTES, CLIENT_SCRIPT_PATH, CLIENT_SCRIPT_SHA256, CLIENT_STYLE_BYTES,
    CLIENT_STYLE_PATH, CLIENT_STYLE_SHA256,
};

/// Media type for an embedded immutable asset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssetContentType {
    /// An executable JavaScript client bundle.
    JavaScript,
    /// A cascading style sheet.
    Css,
}

impl AssetContentType {
    /// Return the canonical UTF-8 HTTP `Content-Type` value for this asset.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::JavaScript => "text/javascript; charset=utf-8",
            Self::Css => "text/css; charset=utf-8",
        }
    }
}

/// A compile-time asset ready for an HTTP adapter to serve.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EmbeddedAsset {
    /// Exact public URL path at which the asset must be served.
    pub path: &'static str,
    /// Media type to send in the HTTP `Content-Type` header.
    pub content_type: AssetContentType,
    /// Lowercase hexadecimal SHA-256 digest of [`Self::bytes`].
    pub sha256: &'static str,
    /// Immutable asset body compiled into the renderer crate.
    pub bytes: &'static [u8],
}

impl EmbeddedAsset {
    /// HTTP cache policy for the content-addressed immutable asset.
    pub const CACHE_CONTROL: &'static str = "public, max-age=31536000, immutable";
}

/// Asset paths that the server places in each SSR request model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientAssetManifest {
    /// Exact public path to the client-side JavaScript entry point.
    pub script_path: &'static str,
    /// Exact public paths to stylesheets required by rendered pages.
    pub stylesheet_paths: &'static [&'static str],
}

const STYLESHEETS: &[&str] = &[CLIENT_STYLE_PATH];

const SCRIPT: EmbeddedAsset = EmbeddedAsset {
    path: CLIENT_SCRIPT_PATH,
    content_type: AssetContentType::JavaScript,
    sha256: CLIENT_SCRIPT_SHA256,
    bytes: CLIENT_SCRIPT_BYTES,
};

const STYLE: EmbeddedAsset = EmbeddedAsset {
    path: CLIENT_STYLE_PATH,
    content_type: AssetContentType::Css,
    sha256: CLIENT_STYLE_SHA256,
    bytes: CLIENT_STYLE_BYTES,
};

/// Return the exact client paths compiled into this binary.
pub const fn client_assets() -> ClientAssetManifest {
    ClientAssetManifest {
        script_path: CLIENT_SCRIPT_PATH,
        stylesheet_paths: STYLESHEETS,
    }
}

/// Look up an immutable client asset by its exact public path.
///
/// Query strings, percent-decoding, and path normalization belong at the HTTP
/// boundary; accepting only an exact known path makes traversal impossible.
pub fn find_asset(path: &str) -> Option<EmbeddedAsset> {
    match path {
        CLIENT_SCRIPT_PATH => Some(SCRIPT),
        CLIENT_STYLE_PATH => Some(STYLE),
        _ => None,
    }
}
