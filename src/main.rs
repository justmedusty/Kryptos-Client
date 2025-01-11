use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::exit;
use std::sync::{Arc, RwLock};
use std::{env, io};
use std::thread::spawn;

static ERROR: i32 = 1;
static SUCCESS: i32 = 0;
type LockedStream = Arc<RwLock<TcpStream>>;

fn main() {
    let args: Vec<String> = env::args().collect();
    if (args.len() < 3) {
        println!("Usage : telnet server_ip port");
        exit(ERROR);
    }
    if (args[0] == "--help") {
        println!("Usage : telnet server_ip port");
        exit(ERROR);
    }

    if (args[0] == "--version") {
        println!("telnet client version {}", env!("CARGO_PKG_VERSION"));
        exit(ERROR);
    }

    let ip = &args[1];
    let port = &args[2];

    let int_port = port.parse::<i32>().unwrap();

    let result = TcpStream::connect(format!("{}:{}", ip, port));

    if(result.is_ok()) {
        let mut stream = result.unwrap();
        let wrapped_stream = Arc::new(RwLock::new(stream));
        let read_reference = Arc::clone(&wrapped_stream);
        spawn(move || {
            client_read_routine(Arc::clone(&wrapped_stream));
        });

        client_input_routine(read_reference);

    }
}
fn client_read_routine(tcp_stream: LockedStream) {
    loop {
        let mut buffer = String::new();
        {
            let mut stream = tcp_stream.write().unwrap();
            stream.set_nonblocking(true).unwrap();
            match stream.read_to_string(&mut buffer) {
                Ok(x) => x,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(_) => exit(ERROR),
            };
            println!("{}", buffer);
        }
        buffer.clear();
    }
}
fn client_input_routine(stream: LockedStream) {
    loop {
        print!("> ");
        io::stdout().flush().unwrap();

        let mut line = String::new();

        io::stdin().read_line(&mut line).unwrap();

        let line = line.trim();

        if line == "exit" {
            exit(0);
        }

        {
            let mut stream = stream.write().unwrap();
            stream.write(line.as_bytes()).unwrap();
        }
    }
}
