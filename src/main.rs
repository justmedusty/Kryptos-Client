mod arg_handling;
mod cryptography;

use crate::arg_handling::arg_handling::arg_handling::{EncryptionInfo, KeySize};
use crate::cryptography::aes::{AESContext, AesMode, AesSize};
use crate::cryptography::cryptography::EncryptionContext;
use crate::cryptography::rc4::Rc4State;
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
type StateMachine = Arc<Mutex<EncryptionContext>>;

fn main() {
    let args: Vec<String> = env::args().collect();
    let config = arg_handling::arg_handling::arg_handling::parse_arguments(args); // arg_handling::arg_handling::arg_handling::arg_handling::arg_handling

    let ip = config.ip;
    let port = config.port;
    let session_key = config.key;

    let mut state = match config.enc_type {
        EncryptionInfo::AesCbc => match session_key.len().into() {
            KeySize::Size128 => EncryptionContext::new(AESContext::new(
                AesMode::CBC,
                AesSize::S128,
                Some(session_key.as_bytes()),
            )),
            KeySize::Size192 => EncryptionContext::new(AESContext::new(
                AesMode::CBC,
                AesSize::S192,
                Some(session_key.as_bytes()),
            )),
            KeySize::Size256 => EncryptionContext::new(AESContext::new(
                AesMode::CBC,
                AesSize::S256,
                Some(session_key.as_bytes()),
            )),
        },
        EncryptionInfo::AesCtr => match session_key.len().into() {
            KeySize::Size128 => EncryptionContext::new(AESContext::new(
                AesMode::CTR,
                AesSize::S128,
                Some(session_key.as_bytes()),
            )),
            KeySize::Size192 => EncryptionContext::new(AESContext::new(
                AesMode::CTR,
                AesSize::S192,
                Some(session_key.as_bytes()),
            )),
            KeySize::Size256 => EncryptionContext::new(AESContext::new(
                AesMode::CTR,
                AesSize::S256,
                Some(session_key.as_bytes()),
            )),
        },
        EncryptionInfo::AesEcb => match session_key.len().into() {
            KeySize::Size128 => EncryptionContext::new(AESContext::new(
                AesMode::ECB,
                AesSize::S128,
                Some(session_key.as_bytes()),
            )),
            KeySize::Size192 => EncryptionContext::new(AESContext::new(
                AesMode::ECB,
                AesSize::S192,
                Some(session_key.as_bytes()),
            )),
            KeySize::Size256 => EncryptionContext::new(AESContext::new(
                AesMode::ECB,
                AesSize::S256,
                Some(session_key.as_bytes()),
            )),
        },
        EncryptionInfo::Rc4 => match session_key.len().into() {
            KeySize::Size128 => EncryptionContext::new(Rc4State::new(Some(session_key.as_bytes()))),
            KeySize::Size192 => EncryptionContext::new(Rc4State::new(Some(session_key.as_bytes()))),
            KeySize::Size256 => EncryptionContext::new(Rc4State::new(Some(session_key.as_bytes()))),
        },
    };

    state.context.set_key(session_key.as_bytes());
    let encryption_context = Arc::new(Mutex::new(state));
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
        let encryption_context_clone = encryption_context.clone();
        spawn(move || {
            client_read_routine(Arc::clone(&wrapped_stream), encryption_context_clone);
        });

        client_input_routine(read_reference, encryption_context);
    }
}
fn client_read_routine(
    tcp_stream: LockedStream,
    encryption_context: Arc<Mutex<EncryptionContext>>,
) {
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
                let mut encryption_context_stream = match encryption_context.lock() {
                    Ok(x) => x,
                    Err(_) => continue,
                };

                /*
                   Drop the rc4 stream after decrypting so that the other thread can acquire the lock when it needs
                   to
                */
                buffer.resize(_n, 0);
                decrypted_buffer.resize(_n, 0);
                encryption_context_stream
                    .context
                    .decrypt(&mut buffer, &mut decrypted_buffer);
                drop(encryption_context_stream);

                /*
                   Print the data that we read on the socket and 0 the buffer up until the point we just read to
                   We do this to avoid iterating the entire buffer every time
                */
                for byte in &decrypted_buffer {
                    print!("{}", *byte as char);
                }
                println!()
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
        let mut encrypted_buffer = vec![0; line.len()];

        let mut rc4_unlocked = rc4.lock().unwrap();
        rc4_unlocked
            .context
            .encrypt(&mut line.as_bytes().to_vec(), &mut encrypted_buffer);
        drop(rc4_unlocked);

        let mut stream = match stream.write() {
            Ok(x) => x,
            Err(_) => {
                println!("Acquiring write lock on stream failed");
                exit(ERROR);
            }
        };
        match stream.write(encrypted_buffer.as_slice()) {
            Ok(x) => x,
            Err(_) => {
                println!("Failed to write line to stream");
                exit(ERROR);
            }
        };
        drop(stream);
    }
}
