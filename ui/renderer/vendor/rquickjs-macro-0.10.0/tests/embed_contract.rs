#![allow(dead_code)]

#[path = "../src/common.rs"]
mod common;
#[path = "../src/embed.rs"]
mod embed;

use proc_macro2::TokenStream;
use quote::{format_ident, quote};

struct ManifestDirectoryGuard(Option<std::ffi::OsString>);

impl Drop for ManifestDirectoryGuard {
    fn drop(&mut self) {
        if let Some(value) = self.0.take() {
            std::env::set_var("CARGO_MANIFEST_DIR", value);
        }
    }
}

#[test]
fn parses_explicit_and_implicit_module_paths() {
    let modules = syn::parse2::<embed::EmbedModules>(quote! {
        "Hello world": "foo",
        "bar"
    })
    .unwrap();

    assert_eq!(modules.0.len(), 2);
    let mut modules = modules.0.iter();
    let explicit = modules.next().unwrap();
    assert_eq!(explicit.name.value(), "Hello world");
    assert_eq!(explicit.path.as_ref().unwrap().1.value(), "foo");
    let implicit = modules.next().unwrap();
    assert_eq!(implicit.name.value(), "bar");
    assert!(implicit.path.is_none());
    assert!(modules.next().is_none());
}

#[test]
fn missing_manifest_directory_is_a_diagnostic_instead_of_a_panic() {
    let guard = ManifestDirectoryGuard(std::env::var_os("CARGO_MANIFEST_DIR"));
    std::env::remove_var("CARGO_MANIFEST_DIR");
    let modules = syn::parse2::<embed::EmbedModules>(quote!("relative.js")).unwrap();

    let error = embed::embed(modules).unwrap_err();
    assert!(error
        .to_string()
        .starts_with("CARGO_MANIFEST_DIR is unavailable while resolving embedded module path:"));

    drop(guard);
}

#[cfg(not(feature = "phf"))]
#[test]
fn expands_ordered_bundle_entries() {
    let entries =
        embed::to_entries(vec![("test_module".to_string(), vec![1_u8, 2, 3, 4])].into_iter());
    let crate_name = format_ident!("rquickjs");
    let actual = embed::expand_for_crate(&entries, &crate_name);
    let expected: TokenStream = quote! {
        rquickjs::loader::bundle::Bundle(&[
            ("test_module", &[1u8, 2u8, 3u8, 4u8])
        ])
    };

    assert_eq!(actual.to_string(), expected.to_string());
}

#[cfg(feature = "phf")]
#[test]
fn expands_ordered_phf_bundle_entries() {
    let entries =
        embed::to_entries(vec![("test_module".to_string(), vec![1_u8, 2, 3, 4])].into_iter());
    let crate_name = format_ident!("rquickjs");
    let actual = embed::expand_for_crate(&entries, &crate_name);
    let expected: TokenStream = quote! {
        rquickjs::loader::bundle::Bundle(&rquickjs::phf::Map {
            key: 16287231350648472473u64,
            disps: &[(0u32, 0u32)],
            entries: &[("test_module", &[1u8, 2u8, 3u8, 4u8])],
        })
    };

    assert_eq!(actual.to_string(), expected.to_string());
}
