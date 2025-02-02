use crate::cryptography::cryptography::Encryption;
use rand::RngCore;

pub const KEY_SIZE_BYTES: usize = 32;

#[derive(Debug)]
pub struct Rc4State {
    s: [u8; KEY_SIZE_BYTES],
    i: usize,
    j: usize,
    key: Rc4Key,
}

#[derive(Debug)]
pub struct Rc4Key {
    key: [u8; KEY_SIZE_BYTES],
}

impl Rc4Key {
    fn new(key: [u8; KEY_SIZE_BYTES]) -> Rc4Key {
        Rc4Key { key }
    }
}

impl Rc4State {
    /// Creates a new Rc4State object with a randomly generated key and default values for the s array, i, j
    pub fn new() -> Self {
        let mut new = Self {
            s: [0; KEY_SIZE_BYTES],
            i: 0,
            j: 0,
            key: Rc4Key::new([0; KEY_SIZE_BYTES]), // Initialize with a default key
        };

        new.initialize();
        new
    }

    pub fn initialize(&mut self) {
        self.generate_key();
    }

    /// Generates a key for your Rc4State object, this is called automatically on invocation of ::new however you can call it again if you wish to regenerate a new key
    /// The key is of size 256 bytes (4096 bits)
    pub fn generate_key(&mut self) {
        let mut key = [0u8; KEY_SIZE_BYTES];
        rand::rng().fill_bytes(&mut key); // Fixed to use a random generator
        self.key = Rc4Key::new(key);
    }

    /// key_scheduling sets up the S array (initial key stream) with initial values getting ready to begin the encryption process.
    fn key_scheduling(&mut self) {
        let key = &self.key.key;

        // Initialize the s array to the range [0..255]
        for i in 0..KEY_SIZE_BYTES {
            self.s[i] = i as u8;
        }

        let mut j = 0;

        for i in 0..KEY_SIZE_BYTES {
            j = (j + self.s[i] as usize + key[i] as usize) % KEY_SIZE_BYTES;
            self.s.swap(i, j);
        }

        self.i = 0;
        self.j = 0;
    }

    /// prga (pseudo-random generator algorithm) sets up the final keystream buffer with pseudo random bytes derived from the initial keystream generated in key_scheduling
    fn prga(&mut self, output_buffer: &mut [u8]) {
        self.key_scheduling();
        for byte in output_buffer {
            self.i = (self.i + 1) % KEY_SIZE_BYTES;
            self.j = (self.j + self.s[self.i] as usize) % KEY_SIZE_BYTES;
            self.s.swap(self.i, self.j);
            let k = self.s[(self.s[self.i] as usize + self.s[self.j] as usize) % KEY_SIZE_BYTES];
            *byte = k;
        }
    }
}

impl Encryption for Rc4State {
    fn initialize_context(&mut self) {
        self.initialize();
    }

    fn encrypt(&mut self, input: &mut Vec<u8>, output: &mut Vec<u8>) {
        let mut keystream = vec![0u8; input.len()];

        if output.len() < input.len() {
            println!("RC4 encrypt: output buffer too short");
            return;
        }

        self.prga(&mut keystream);

        for (i, &input_byte) in input.iter().enumerate() {
            output[i] = keystream[i] ^ input_byte;
        }
    }

    fn decrypt(&mut self, input: &mut Vec<u8>, output:  &mut Vec<u8>) {
        self.encrypt(input, output);
    }

    fn set_key(&mut self, key: &[u8]) {
        if key.len() != KEY_SIZE_BYTES {
            println!("Key size is not correct! Expected {KEY_SIZE_BYTES}");
            return;
        }

        self.key.key = match key.try_into() {
            Ok(x) => x,
            Err(_) => self.key.key,
        };
    }
}
