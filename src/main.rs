mod cryptography;

use crate::cryptography::rc4::{Rc4State, KEY_SIZE_BYTES};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::exit;
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{sleep, spawn};
use std::time::Duration;
use std::{env, io};
use crate::cryptography::cryptography::EncryptionContext;

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
        println!("{}",session_key.len());
        eprintln!("Invalid session key! Must be of length {KEY_SIZE_BYTES}. Ask the server administrator for the session key.");
        exit(ERROR);
    }
    let mut state = EncryptionContext::new(Rc4State::new());

    state.context.set_key(&session_key);
    let rc4 = Arc::new(Mutex::new(state));
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
fn client_read_routine(tcp_stream: LockedStream, rc4: Arc<Mutex<EncryptionContext>>) {
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
                eprintln!("Remote server has closed the connection\n");
                exit(ERROR);
            }
            Ok(_n) => {
                let mut decrypted_buffer = buffer.clone();

                let mut rc4_stream = match rc4.lock() {
                    Ok(x) => x,
                    Err(_) => continue,
                };

                /*
                   Drop the rc4 stream after decrypting so that the other thread can acquire the lock when it needs
                   to
                */
                rc4_stream.context.decrypt(&mut buffer, &mut decrypted_buffer);
                drop(rc4_stream);

                //Resize the buffer so that we don't print any junk in the rest of the buffer
                decrypted_buffer.resize(_n, 0);

                let data = String::from_utf8_lossy(&decrypted_buffer);

                /*
                   Print the data that we read on the socket and 0 the buffer up until the point we just read to
                   We do this to avoid iterating the entire buffer every time
                */
                print!("{}", data);

                for mut byte in buffer[.._n].iter_mut() {
                    *byte = 0;
                }
            }
            //Since we require non blocking reads due to the lock scheme, just continue the loop, dropping the lock
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(_) => exit(ERROR),
        };

        drop(stream);
        io::stdout().flush().unwrap();
    }
}

/*
   As per the explicit drops due to the nature of both threads requiring access we need to manually drop (or use scope blocks but
   manual drops are more explicit which is good) everything once we're done,otherwise locks would be held longer than is
   absolutely necessary
*/
fn client_input_routine(stream: LockedStream, rc4: Arc<Mutex<EncryptionContext>>) {
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
        rc4_unlocked.context.encrypt(&mut line.as_bytes().to_vec(), &mut encrypted_buffer);
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
    }
}
