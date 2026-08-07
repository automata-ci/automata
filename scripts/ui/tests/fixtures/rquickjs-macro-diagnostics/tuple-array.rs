use rquickjs_macro::methods;

struct Widget;

#[methods(crate = "rquickjs_core")]
impl (Widget, [u8; 4]) {}

fn main() {}
