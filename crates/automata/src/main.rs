#![forbid(unsafe_code)]

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    automata::run().await
}
