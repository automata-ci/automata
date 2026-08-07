use std::{env, path::Path};

use crate::common::crate_ident;
use proc_macro2::{Ident, Span, TokenStream};
use quote::{format_ident, quote};
use rquickjs_core::{Context, Module, Result as JsResult, Runtime, WriteOptions};
use syn::{
    parse::{Parse, ParseStream},
    punctuated::Punctuated,
    Error, LitStr, Result, Token,
};

/// A line of embedded modules.
pub struct EmbedModule {
    pub name: LitStr,
    pub path: Option<(Token![:], LitStr)>,
}

impl Parse for EmbedModule {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let name = input.parse::<LitStr>()?;
        let path = if input.peek(Token![:]) {
            let colon = input.parse()?;
            let name = input.parse()?;
            Some((colon, name))
        } else {
            None
        };

        Ok(EmbedModule { path, name })
    }
}

/// The parsing struct for embedded modules.
pub struct EmbedModules(pub Punctuated<EmbedModule, Token![,]>);

impl Parse for EmbedModules {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let res = input.parse_terminated(EmbedModule::parse, Token![,])?;
        Ok(EmbedModules(res))
    }
}

/// Implementation of the macro
pub fn embed(modules: EmbedModules) -> Result<TokenStream> {
    let mut files = Vec::new();
    for f in modules.0.into_iter() {
        let path = f
            .path
            .as_ref()
            .map(|x| x.1.value())
            .unwrap_or_else(|| f.name.value());

        let path = Path::new(&path);

        let path = if path.is_relative() {
            let manifest_directory = env::var("CARGO_MANIFEST_DIR").map_err(|error| {
                Error::new(
                    f.name.span(),
                    format_args!(
                        "CARGO_MANIFEST_DIR is unavailable while resolving embedded module path: {error}"
                    ),
                )
            })?;
            let full_path = Path::new(&manifest_directory).join(path);
            match full_path.canonicalize() {
                Ok(x) => x,
                Err(e) => {
                    return Err(Error::new(
                        f.name.span(),
                        format_args!(
                            "Error loading embedded js module from path `{}`: {}",
                            full_path.display(),
                            e
                        ),
                    ));
                }
            }
        } else {
            path.to_owned()
        };

        let source = match std::fs::read_to_string(&path) {
            Ok(x) => x,
            Err(e) => {
                return Err(Error::new(
                    f.name.span(),
                    format_args!(
                        "Error loading embedded js module from path `{}`: {}",
                        path.display(),
                        e
                    ),
                ));
            }
        };
        files.push((f.name.value(), source));
    }

    let res = (|| -> JsResult<Vec<(String, Vec<u8>)>> {
        let rt = Runtime::new()?;
        let ctx = Context::full(&rt)?;

        let mut modules = Vec::new();

        ctx.with(|ctx| -> JsResult<()> {
            for f in files.into_iter() {
                let bc = Module::declare(ctx.clone(), f.0.clone(), f.1)?
                    .write(WriteOptions::default())?;
                modules.push((f.0, bc));
            }
            Ok(())
        })?;
        Ok(modules)
    })();

    let res = match res {
        Ok(x) => x,
        Err(e) => {
            return Err(Error::new(
                Span::call_site(),
                format_args!("Error compiling embedded js module: {}", e),
            ));
        }
    };

    let res = to_entries(res.into_iter());

    expand(&res)
}

pub(super) fn to_entries(
    modules: impl Iterator<Item = (String, Vec<u8>)>,
) -> Vec<(String, TokenStream)> {
    modules
        .map(|(name, data)| (name, quote! { &[#(#data),*] }))
        .collect::<Vec<_>>()
}

#[cfg(feature = "phf")]
pub fn expand(modules: &[(String, TokenStream)]) -> Result<TokenStream> {
    let lib_crate = crate_ident()?;
    let lib_crate = format_ident!("{}", lib_crate);
    Ok(expand_for_crate(modules, &lib_crate))
}

#[cfg(feature = "phf")]
pub(super) fn expand_for_crate(
    modules: &[(String, TokenStream)],
    lib_crate: &Ident,
) -> TokenStream {
    let keys = modules.iter().map(|(x, _)| x.clone()).collect::<Vec<_>>();

    let state = phf_generator::generate_hash(&keys);

    let key = state.key;
    let disps = state.disps.iter().map(|&(d1, d2)| quote!((#d1, #d2)));
    let entries = state.map.iter().map(|&idx| {
        let key = &modules[idx].0;
        let value = &modules[idx].1;
        quote!((#key, #value))
    });

    quote! {
        #lib_crate::loader::bundle::Bundle(& #lib_crate::phf::Map{
            key: #key,
            disps: &[#(#disps),*],
            entries: &[#(#entries),*],
        })
    }
}

#[cfg(not(feature = "phf"))]
pub fn expand(modules: &[(String, TokenStream)]) -> Result<TokenStream> {
    let lib_crate = crate_ident()?;
    let lib_crate = format_ident!("{}", lib_crate);
    Ok(expand_for_crate(modules, &lib_crate))
}

#[cfg(not(feature = "phf"))]
pub(super) fn expand_for_crate(
    modules: &[(String, TokenStream)],
    lib_crate: &Ident,
) -> TokenStream {
    let entries = modules.iter().map(|(name, data)| {
        quote! { (#name,#data)}
    });
    quote! {
        #lib_crate::loader::bundle::Bundle(&[#(#entries),*])
    }
}
