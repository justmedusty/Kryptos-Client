mod rc4;

use crate::rc4::rc4::{Rc4State, KEY_SIZE_BYTES};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::exit;
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{sleep, spawn};
use std::time::Duration;
use std::{env, io};

static ERROR: i32 = 1;
static SUCCESS: i32 = 0;
type LockedStream = Arc<RwLock<TcpStream>>;
type Rc4StateMachine = Arc<Mutex<Rc4State>>;

fn main() {
    let args: Vec<String> = env::args().collect();

    if (args.len() > 4) {
        println!("Too many arguments!");
        println!("Usage : telnet server_ip port session_key");
        println!("Try --help for help.");
        exit(ERROR);
    }

    if { args.len() < 3 } {
        println!("Usage : telnet server_ip port session_key");
        println!("Try --help for help.");
        exit(ERROR);
    }
    if (args[1] == "--help") {
        println!("Usage : telnet server_ip port session_key");
        println!("This is a very simple telnet server client written in Rust.");
        println!("There is a multithreaded server to pair on my github if would like to play around with it.");
        println!("Options: --help, --version");
        exit(SUCCESS);
    }

    if (args[1] == "--version") {
        println!("telnet client version {}", env!("CARGO_PKG_VERSION"));
        exit(SUCCESS);
    }

    if { args.len() < 4 } {
        println!("Usage : telnet server_ip port session_key");
        println!("Try --help for help.");
        exit(ERROR);
    }

    let ip = &args[1];
    let port = &args[2];
    let session_key = args[3].as_bytes().to_owned();

    if session_key.len() != KEY_SIZE_BYTES {
        eprintln!("Invalid session key! Must be of length {KEY_SIZE_BYTES}. ASk the server administrator for the session key.");
        exit(ERROR);
    }
    let mut rc4_state = Rc4State::new();

    rc4_state.set_key(&session_key);
    let rc4 = Arc::new(Mutex::new(rc4_state));
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
        let rc4_clone = rc4.clone();
        spawn(move || {
            client_read_routine(Arc::clone(&wrapped_stream), rc4_clone);
        });

        client_input_routine(read_reference, rc4);
    }
}
fn client_read_routine(tcp_stream: LockedStream, rc4: Rc4StateMachine) {
    loop {
        let mut buffer = vec![0; 1024];
        sleep(Duration::from_millis(25));

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
            Ok(0) => {
                continue;
            }
            Ok(_n) => {
                let mut decrypted_buffer = buffer.clone();

                let mut rc4_stream = match rc4.lock() {
                    Ok(x) => x,
                    Err(_) => continue,
                };
                rc4_stream.decrypt(&buffer, &mut decrypted_buffer);
                drop(rc4_stream);
                decrypted_buffer.resize(_n, 0);
                let data = String::from_utf8_lossy(&decrypted_buffer);
                if data.len() > 0 {
                    print!("{}", data);
                }
                for mut byte in buffer {
                    byte = 0;
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(_) => exit(ERROR),
        };
        drop(stream);

        io::stdout().flush().unwrap();
    }
}
fn client_input_routine(stream: LockedStream, rc4: Rc4StateMachine) {
    loop {
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
        let mut encrypted_buffer = vec![0; 4096];
        encrypted_buffer.truncate(line.len());

        let mut rc4_unlocked = rc4.lock().unwrap();
        rc4_unlocked.encrypt(line.as_bytes(), &mut encrypted_buffer);
        drop(rc4_unlocked);

        let mut stream = match stream.write() {
            Ok(x) => x,
            Err(_) => {
                println!("Acquiring write lock on stream failed");
                exit(ERROR);
            }
        };
        encrypted_buffer.resize(line.len(), 0);
        match stream.write_all(encrypted_buffer.as_slice()) {
            Ok(x) => x,
            Err(_) => {
                println!("Failed to write line to stream");
                exit(ERROR);
            }
        };
        drop(stream);

        sleep(Duration::from_millis(25));
    }
}
