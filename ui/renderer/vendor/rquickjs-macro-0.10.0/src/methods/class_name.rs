use syn::{spanned::Spanned, Error, Result, Type};

const UNSUPPORTED_SELF_TYPE: &str =
    "unsupported #[methods] self type; expected a path, parenthesized type, or tuple of supported types";

pub(super) fn get_class_name(ty: &Type) -> Result<String> {
    match ty {
        Type::Paren(parenthesized) => get_class_name(&parenthesized.elem),
        Type::Path(path) => path
            .path
            .segments
            .first()
            .map(|segment| segment.ident.to_string())
            .ok_or_else(|| Error::new(path.span(), UNSUPPORTED_SELF_TYPE)),
        Type::Tuple(tuple) => {
            let names = tuple
                .elems
                .iter()
                .map(get_class_name)
                .collect::<Result<Vec<_>>>()?;
            Ok(format!("tuple_{}", names.join("_")))
        }
        unsupported => Err(Error::new(unsupported.span(), UNSUPPORTED_SELF_TYPE)),
    }
}
