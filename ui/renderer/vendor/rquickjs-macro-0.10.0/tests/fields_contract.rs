#![allow(dead_code)]

#[path = "../src/attrs.rs"]
mod attrs;
#[path = "../src/common.rs"]
mod common;
#[path = "../src/fields.rs"]
mod fields;

use fields::Fields;
use quote::format_ident;
use syn::{parse_quote, ItemStruct};

#[test]
fn ordinary_fields_without_accessor_options_expand_to_no_property() {
    let named: ItemStruct = parse_quote! {
        struct Named {
            ordinary: u32,
            #[qjs(get)]
            readable: u32,
        }
    };
    let Fields::Named(named) = Fields::from_fields(named.fields).unwrap() else {
        panic!("expected named fields");
    };
    let crate_name = format_ident!("rquickjs");

    assert!(named[0].expand_property_named(&crate_name, None).is_empty());
    assert!(!named[1].expand_property_named(&crate_name, None).is_empty());

    let unnamed: ItemStruct = parse_quote! {
        struct Unnamed(u32, #[qjs(set)] u64);
    };
    let Fields::Unnamed(unnamed) = Fields::from_fields(unnamed.fields).unwrap() else {
        panic!("expected unnamed fields");
    };

    assert!(unnamed[0]
        .expand_property_unnamed(&crate_name, 0)
        .is_empty());
    assert!(!unnamed[1]
        .expand_property_unnamed(&crate_name, 1)
        .is_empty());
    assert!(!unnamed[0]
        .expand_trace_body_unnamed(&crate_name, 0)
        .is_empty());
}
