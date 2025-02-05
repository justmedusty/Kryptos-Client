pub mod arg_handling {
    use crate::arg_handling::arg_handling::arg_handling::KeySize::Size256;
    use crate::{ERROR, SUCCESS};
    use std::process::exit;
    /*
           Enum we will use to pass encryption info for creation of context
        */
    #[derive(Clone, Copy)]
    pub enum EncryptionInfo {
        AesCbc,
        AesCtr,
        AesEcb,
        Rc4,
    }

    #[derive(Clone, Copy)]
    pub enum KeySize {
        Size128,
        Size192,
        Size256,
    }
    impl Into<usize> for KeySize {
        fn into(self) -> usize {
            match self {
                KeySize::Size128 => 128,
                KeySize::Size192 => 192,
                KeySize::Size256 => 256,
            }
        }
    }

    impl From<usize> for KeySize {
        fn from(value: usize) -> Self {
            match value {
                128 => KeySize::Size128,
                192 => KeySize::Size192,
                256 => KeySize::Size256,
                _ => Size256, // default to 256
            }
        }
    }

    pub struct KryptosConfig {
        pub enc_type: EncryptionInfo,
        pub key: String,
        pub port: u16,
        pub ip: String,
    }

    pub fn parse_arguments(args: Vec<String>) -> KryptosConfig {
        let use_key: bool = args.len() == 5;
        if (args.len() > 5) {
            println!("Too many arguments!");
            println!("Usage: kryptos-client ip port encryption-type key");
            println!("Try --help for help.");
            exit(ERROR);
        }

        if { args.len() < 2 } {
            println!("Usage: kryptos-client ip port encryption-type key");
            println!("Try --help for help.");
            exit(ERROR);
        }
        if (args[1] == "--help") {
            println!("Usage: kryptos-client ip port encryption-type key");
            println!("Encryption Options: AesCbc, AesCtr, AesEcb (unsafe), Rc4 (unsafe)");
            println!("Key Size Options: 128, 192, 256");
            println!("This is a simple encrypted telnet chat client written in Rust.");
            println!("The server is available on my github");
            println!("Options: --help, --version");
            exit(SUCCESS);
        }

        if (args[1] == "--version") {
            println!("Kryptos client version {}", env!("CARGO_PKG_VERSION"));
            exit(SUCCESS);
        }

        if { args.len() < 5 } {
            println!("Usage: kryptos-client ip port encryption-type key");
            println!("Try --help for help.");
            exit(ERROR);
        }

        let ip = args[1].clone();

        let port = match args[2].parse::<u16>() {
            Ok(x) if x < 1024 => {
                eprintln!("Port must not be in the reserved range!");
                exit(ERROR);
            }
            Ok(x) => x,
            Err(_) => {
                eprintln!("Error occurred while parsing port!");
                exit(ERROR);
            }
        };

        let encryption_type = match args[3].as_str() {
            "AesCbc" => EncryptionInfo::AesCbc,
            "AesCtr" => EncryptionInfo::AesCtr,
            "AesEcb" => EncryptionInfo::AesEcb,
            "Rc4" => EncryptionInfo::Rc4,
            _ => {
                eprintln!("Invalid encryption type!");
                eprintln!("Try --help for help.");
                exit(ERROR);
            }
        };
        let key = args[4].to_string();

        let actual_size = key.len();

        if ((key.len()) * 8 != 128 && (key.len()) * 8 != 192 && (key.len() * 8) != 256) {
            eprintln!("Invalid key!");
            eprintln!(
                "Valid key sizes are 128, 192, 256! The provided key was of length {}.",
                actual_size * 8
            );
            exit(ERROR);
        }

        let config = KryptosConfig {
            enc_type: encryption_type,
            key,
            port,
            ip,
        };

        config
    }
}
