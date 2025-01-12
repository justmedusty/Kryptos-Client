use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::exit;
use std::sync::{Arc, RwLock};
use std::thread::spawn;
use std::{env, io};

static ERROR: i32 = 1;
static SUCCESS: i32 = 0;
type LockedStream = Arc<RwLock<TcpStream>>;

fn main() {
    let args: Vec<String> = env::args().collect();
    if (args.len() < 3) {
        println!("Usage : telnet server_ip port");
        exit(ERROR);
    }

    if(args.len() > 3){
        println!("Too many arguments!");
        println!("Usage : telnet server_ip port");
        println!("Try --help for help.");
    }
    if (args[0] == "--help") {
        println!("Usage : telnet server_ip port");
        println!("Options: --help, --version");
        exit(SUCCESS);
    }

    if (args[0] == "--version") {
        println!("telnet client version {}", env!("CARGO_PKG_VERSION"));
        exit(SUCCESS);
    }

    let ip = &args[1];
    let port = &args[2];

    let result = TcpStream::connect(format!("{}:{}", ip, port));

    if (result.is_ok()) {
        let mut stream = match result {
            Ok(x) => x,
            Err(_) => {
                println!("Error unwrapping result");
                exit(ERROR);
            }
        };
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
        let mut buffer = vec![0; 1024];
        {
            let mut stream = match tcp_stream.write() {
                Ok(x) => x,
                Err(_) => {
                    println!("TCP stream lock acquisition failed\n");
                    exit(ERROR);
                }
            };
            match stream.set_nonblocking(true) {
                Ok(x) => x,
                Err(_) => {
                    println!("Setting socket to non blocking failed\n");
                    exit(ERROR);
                }
            };
            match stream.read(&mut buffer) {
                Ok(0) => continue,
                Ok(n) => {
                    buffer.truncate(n);
                    let data = String::from_utf8_lossy(&buffer);
                    println!("Received: {}", data);
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(_) => exit(ERROR),
            };
            match io::stdout().flush() {
                Ok(x) => x,
                Err(_) => {
                    println!("Failed to flush stdout");
                    exit(ERROR);
                }
            };
        }
    }
}
fn client_input_routine(stream: LockedStream) {
    loop {
        match io::stdout().flush() {
            Ok(x) => x,
            Err(_) => {
                println!("Failed to flush stdout");
                exit(ERROR);
            }
        };

        let mut line = String::new();

        match io::stdin().read_line(&mut line) {
            Ok(x) => x,
            Err(_) => {
                println!("read_line triggered error");
                exit(ERROR);
            }
        };

        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let mut stream = match stream.write() {
            Ok(x) => x,
            Err(_) => {
                println!("Acquiring write lock on stream failed");
                exit(ERROR);
            }
        };
        match stream.write_all(line.as_bytes()) {
            Ok(x) => x,
            Err(_) => {
                println!("Failed to write line to stream");
                exit(ERROR);
            }
        };
    }
}
