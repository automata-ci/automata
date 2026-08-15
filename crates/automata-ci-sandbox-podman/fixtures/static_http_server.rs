use std::{
    io::{Read as _, Write as _},
    net::TcpListener,
};

fn main() -> std::io::Result<()> {
    if std::env::args().nth(1).as_deref() == Some("--version") {
        println!("automata-docker-live 1");
        return Ok(());
    }
    let listener = TcpListener::bind("0.0.0.0:8080")?;
    println!("automata-docker-live ready");
    for connection in listener.incoming() {
        let mut connection = connection?;
        let mut request = [0_u8; 4096];
        let _read = connection.read(&mut request)?;
        connection.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 24\r\nConnection: close\r\n\r\nautomata-docker-live-ok\n",
        )?;
    }
    Ok(())
}
