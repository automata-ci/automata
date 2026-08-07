use rquickjs_macro::methods;

struct Widget;

#[methods(crate = "rquickjs_core")]
impl &'static Widget {}

fn main() {}
