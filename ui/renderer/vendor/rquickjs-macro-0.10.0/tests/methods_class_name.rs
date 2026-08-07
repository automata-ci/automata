#[path = "../src/methods/class_name.rs"]
mod class_name;

use class_name::get_class_name;
use syn::{parse_quote, Type};

const UNSUPPORTED_SELF_TYPE: &str =
    "unsupported #[methods] self type; expected a path, parenthesized type, or tuple of supported types";

#[test]
fn preserves_supported_path_parenthesized_and_tuple_names() {
    let cases: [(Type, &str); 4] = [
        (parse_quote!(Widget), "Widget"),
        (parse_quote!(module::Widget), "module"),
        (parse_quote!((Widget)), "Widget"),
        (
            parse_quote!((Alpha, module::Beta, (Gamma))),
            "tuple_Alpha_module_Gamma",
        ),
    ];

    for (self_type, expected) in cases {
        assert_eq!(get_class_name(&self_type).unwrap(), expected);
    }
}

#[test]
fn rejects_array_and_other_unsupported_self_types() {
    let unsupported: [Type; 2] = [parse_quote!([u8; 4]), parse_quote!(&'static Widget)];

    for self_type in unsupported {
        let error = get_class_name(&self_type).unwrap_err();
        assert_eq!(error.to_string(), UNSUPPORTED_SELF_TYPE);
        assert!(error
            .into_compile_error()
            .to_string()
            .contains(UNSUPPORTED_SELF_TYPE));
    }
}

#[test]
fn propagates_an_unsupported_nested_tuple_member() {
    let self_type: Type = parse_quote!((Widget, [u8; 4]));
    let error = get_class_name(&self_type).unwrap_err();

    assert_eq!(error.to_string(), UNSUPPORTED_SELF_TYPE);
}
