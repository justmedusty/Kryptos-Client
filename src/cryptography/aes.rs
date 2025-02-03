use crate::cryptography::cryptography::Encryption;
use rand::RngCore;
use std::cmp::PartialEq;

const AES_BLOCK_LENGTH_BYTES: usize = 16;
const AES_KEY_LENGTH_BYTES_MAX: usize = 32;

const NUM_COLUMNS: u8 = 4;

type AesState = [[u8; 4]; 4];

/*
   Sbox and Rsbox as per the NIST standard
*/
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const RSBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

/*
Only the first some of these constants are actually used – up to rcon[10] for AES-128 (as 11 round keys are needed),
*  up to rcon[8] for AES-192, up to rcon[7] for AES-256. rcon[0] is not used in AES algorithm.
*/
const ROUND_CONSTANTS: [u8; 11] = [
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
];

fn get_sbox_number(num: u8) -> u8 {
    SBOX[num as usize]
}
fn get_sbox_inverted(num: u8) -> u8 {
    RSBOX[num as usize]
}

fn x_time(x: u8) -> u8 {
    // Left shift x by 1 position (equivalent to multiplying by 2)
    // The result will be in the 8-bit range, so we need to account for overflow.
    let shifted = x << 1;

    // If the leftmost bit of x is 1 (i.e., x >= 128), we must reduce the result
    // by XORing it with the irreducible polynomial 0x1b (which represents the reduction modulo x^8 + x^4 + x^3 + x + 1).
    let reduction = (x >> 7) & 1; // Extract the leftmost bit

    // If the leftmost bit was 1, reduce the result by XORing with 0x1b
    shifted ^ (reduction * 0x1b)
}

fn multiply(x: u8, y: u8) -> u8 {
    // This function performs multiplication in GF(2^8) (Galois Field) using XOR and the x_time function
    return ((y & 1) * x) ^                               // If the least significant bit of y is 1, add x (no shift)
        ((y >> 1 & 1) * x_time(x)) ^                   // If the second least significant bit of y is 1, add x_time(x) (shifted by 1)
        ((y >> 2 & 1) * x_time(x_time(x))) ^           // If the third bit is 1, add x_time(x_time(x)) (shifted by 2)
        ((y >> 3 & 1) * x_time(x_time(x_time(x)))) ^   // If the fourth bit is 1, add x_time(x_time(x_time(x))) (shifted by 3)
        ((y >> 4 & 1) * x_time(x_time(x_time(x_time(x))))); // If the fifth bit is 1, add x_time(x_time(x_time(x_time(x)))) (shifted by 4)

    // In this process, we're using the binary representation of y to determine how many times
    // to multiply x by powers of x in GF(2^8) (via x_time), and then XOR the results.
    // The multiplication follows the logic of the AES algorithm for multiplication in GF(2^8).
}

/*
    Convert to and from a C-style 2d array.

    AES is column major but I am using a C impl for guidance.
    I can change this but I will have to change all of the transformation
    functions so it is not really worth it
*/
fn as_2d_array(buffer: &[u8]) -> AesState {
    let mut state: AesState = [[0u8; 4]; 4];
    for i in 0..4 {
        for j in 0..4 {
            state[i][j] = buffer[i * 4 + j];
        }
    }
    state
}

fn from_2d_array(state: &AesState) -> [u8; 16] {
    let mut buffer = [0u8; 16];
    for i in 0..4 {
        for j in 0..4 {
            buffer[i * 4 + j] = state[i][j];
        }
    }
    buffer
}

pub enum AesMode {
    CBC, // Cipher block chaining
    ECB, //Codebook
    CTR, // Counter
}

pub enum AesSize {
    S128, // 128-bit key
    S192, // 192-bit key
    S256, //256-bit key
}

pub struct AESContext {
    mode: AesMode,
    size: AesSize,
    //We will just allocate the max bytes rather than have differing allocations
    //it's a small allocation so who cares
    key: [u8; AES_KEY_LENGTH_BYTES_MAX],
    round_keys: [u8; 256], //240 bytes holds all of the round keys with a 256 bit key
    initialization_vector: [u8; AES_BLOCK_LENGTH_BYTES],
}

impl PartialEq<AesSize> for AesSize {
    fn eq(&self, other: &AesSize) -> bool {
        let my_size = match self {
            AesSize::S256 => 256,
            AesSize::S192 => 192,
            AesSize::S128 => 128,
        };

        let other_size = match other {
            AesSize::S256 => 256,
            AesSize::S192 => 192,
            AesSize::S128 => 128,
        };
        my_size == other_size
    }
}

impl AESContext {
    pub fn new(mode: AesMode, size: AesSize, key: Option<&[u8]>) -> Self {
        let mut new = AESContext {
            mode,
            size,
            key: [0u8; 32],
            round_keys: [0u8; 256],
            initialization_vector: [0u8; 16],
        };

        if key.is_some() {
            let key = key.unwrap();
            let key_size = match new.size {
                AesSize::S128 => 128,
                AesSize::S192 => 192,
                AesSize::S256 => 256,
            };
            for i in 0..key_size / 8 {
                new.key[i] = key[i];
            }
        } else {
            let mut key = [0u8; 32];
            rand::rng().fill_bytes(&mut key); // Generate a full key regardless of size it just won't use the extra bytes for sub 256 bit keys

            for (i, byte) in key.iter_mut().enumerate() {
                new.key[i] = *byte;
            }
        }

        /*
            For now we will stick with a singular hard coded IV we will need to come back to this later obviously since the
            IV needs to be unique for every message and stored with the message
        */
        rand::rng().fill_bytes(&mut new.initialization_vector);
        new.initialize_context();

        new
    }
    fn add_round_key(&mut self, round: u8, state: &mut AesState) {
        for i in 0..4 {
            for j in 0..4 {
                state[i][j] ^= self.round_keys
                    [((round * NUM_COLUMNS * 4) + (i as u8 * NUM_COLUMNS) + j as u8) as usize];
            }
        }
    }

    fn sub_bytes(&mut self, state: &mut AesState) {
        for i in 0..4 {
            for j in 0..4 {
                state[j][i] = get_sbox_number(state[j][i]);
            }
        }
    }

    fn inverted_sub_bytes(&mut self, state: &mut AesState) {
        for i in 0..4 {
            for j in 0..4 {
                state[j][i] = get_sbox_inverted(state[j][i]);
            }
        }
    }

    fn shift_rows(&mut self, state: &mut AesState) {
        let mut temp: u8;

        // Rotate first row 1 column to the left
        temp = state[0][1];
        state[0][1] = state[1][1];
        state[1][1] = state[2][1];
        state[2][1] = state[3][1];
        state[3][1] = temp;

        // Rotate second row 2 columns to the left
        temp = state[0][2];
        state[0][2] = state[2][2];
        state[2][2] = temp;

        temp = state[1][2];
        state[1][2] = state[3][2];
        state[3][2] = temp;

        // Rotate third row 3 columns to the left
        temp = state[0][3];
        state[0][3] = state[3][3];
        state[3][3] = state[2][3];
        state[2][3] = state[1][3];
        state[1][3] = temp;
    }

    fn inv_shift_rows(&mut self, state: &mut AesState) {
        let mut temp: u8;
        // Rotate first row 1 column to the right
        temp = state[3][1];
        state[3][1] = state[2][1];
        state[2][1] = state[1][1];
        state[1][1] = state[0][1];
        state[0][1] = temp;

        // Rotate second row 2 columns to the right
        temp = state[0][2];
        state[0][2] = state[2][2];
        state[2][2] = temp;

        temp = state[1][2];
        state[1][2] = state[3][2];
        state[3][2] = temp;

        // Rotate third row 3 columns to the right
        temp = state[0][3];
        state[0][3] = state[1][3];
        state[1][3] = state[2][3];
        state[2][3] = state[3][3];
        state[3][3] = temp;
    }
    fn inv_mix_columns(&mut self, state: &mut AesState) {
        let mut a: u8;
        let mut b: u8;
        let mut c: u8;
        let mut d: u8;

        for i in 0..4 {
            a = state[i][0];
            b = state[i][1];
            c = state[i][2];
            d = state[i][3];

            state[i][0] =
                multiply(a, 0x0e) ^ multiply(b, 0x0b) ^ multiply(c, 0x0d) ^ multiply(d, 0x09);
            state[i][1] =
                multiply(a, 0x09) ^ multiply(b, 0x0e) ^ multiply(c, 0x0b) ^ multiply(d, 0x0d);
            state[i][2] =
                multiply(a, 0x0d) ^ multiply(b, 0x09) ^ multiply(c, 0x0e) ^ multiply(d, 0x0b);
            state[i][3] =
                multiply(a, 0x0b) ^ multiply(b, 0x0d) ^ multiply(c, 0x09) ^ multiply(d, 0x0e);
        }
    }

    fn mix_columns(&mut self, state: &mut AesState) {
        let mut t: u8;
        let mut tmp: u8;
        let mut tm: u8;

        for i in 0..4 {
            t = state[i][0];
            tmp = state[i][0] ^ state[i][1] ^ state[i][2] ^ state[i][3];

            tm = state[i][0] ^ state[i][1];
            tm = x_time(tm);
            state[i][0] ^= tm ^ tmp;

            tm = state[i][1] ^ state[i][2];
            tm = x_time(tm);
            state[i][1] ^= tm ^ tmp;

            tm = state[i][2] ^ state[i][3];
            tm = x_time(tm);
            state[i][2] ^= tm ^ tmp;

            tm = state[i][3] ^ t;
            tm = x_time(tm);
            state[i][3] ^= tm ^ tmp;
        }
    }

    fn key_expansion(&mut self) {
        let mut temp_array: [u8; 4] = [0, 0, 0, 0]; // Used for the column/row operations
        let num_words_in_key = match self.size {
            AesSize::S128 => 4,
            AesSize::S192 => 6,
            AesSize::S256 => 8,
        }; // Number of 32-bit words in the key
        let num_columns = 4; // Number of columns (for AES)
        let num_rounds = match self.size {
            AesSize::S128 => 10,
            AesSize::S192 => 12,
            AesSize::S256 => 14,
        }; // Number of rounds
        let round_key = &mut self.round_keys;

        // The first round key is the key itself.
        for i in 0..num_words_in_key {
            round_key[i * 4] = self.key[i * 4];
            round_key[(i * 4) + 1] = self.key[(i * 4) + 1];
            round_key[(i * 4) + 2] = self.key[(i * 4) + 2];
            round_key[(i * 4) + 3] = self.key[(i * 4) + 3];
        }

        // All other round keys are found from the previous round keys.
        for i in num_words_in_key..num_columns * (num_rounds + 1) {
            let k = (i - 1) * 4;
            temp_array[0] = round_key[k];
            temp_array[1] = round_key[k + 1];
            temp_array[2] = round_key[k + 2];
            temp_array[3] = round_key[k + 3];

            if i % num_words_in_key == 0 {
                // RotWord() function - shifts the 4 bytes in a word to the left
                let tmp = temp_array[0];
                temp_array[0] = temp_array[1];
                temp_array[1] = temp_array[2];
                temp_array[2] = temp_array[3];
                temp_array[3] = tmp;

                // SubWord() function - applies the S-box to each byte
                temp_array[0] = get_sbox_number(temp_array[0]);
                temp_array[1] = get_sbox_number(temp_array[1]);
                temp_array[2] = get_sbox_number(temp_array[2]);
                temp_array[3] = get_sbox_number(temp_array[3]);

                temp_array[0] = temp_array[0] ^ ROUND_CONSTANTS[i / num_words_in_key];
            }
            if self.size == AesSize::S256 && i % num_words_in_key == 4 {
                // SubWord() function for AES256
                temp_array[0] = get_sbox_number(temp_array[0]);
                temp_array[1] = get_sbox_number(temp_array[1]);
                temp_array[2] = get_sbox_number(temp_array[2]);
                temp_array[3] = get_sbox_number(temp_array[3]);
            }
            let j = i * 4;
            let k = (i - num_words_in_key) * 4;
            round_key[j] = round_key[k] ^ temp_array[0];
            round_key[j + 1] = round_key[k + 1] ^ temp_array[1];
            round_key[j + 2] = round_key[k + 2] ^ temp_array[2];
            round_key[j + 3] = round_key[k + 3] ^ temp_array[3];
        }
    }
    fn initialize_context(&mut self) {
        self.key_expansion();
    }

    fn set_initialization_vector(&mut self, iv: &[u8]) {
        self.key_expansion();

        for (i, byte) in iv.iter().enumerate() {
            self.initialization_vector[i] = *byte;
            if i == AES_BLOCK_LENGTH_BYTES {
                break;
            }
        }
    }

    /*
       Main AES cipher function, walks through each round adding the round key and
       mixing bytes. Uses the proper number of rounds based off the size of the
       AES Context object.
    */
    fn cipher(&mut self, buffer: &[u8], output: &mut [u8]) {
        let num_rounds = match self.size {
            AesSize::S128 => 10,
            AesSize::S192 => 12,
            AesSize::S256 => 14,
        };

        let mut state = as_2d_array(buffer);

        self.add_round_key(0, &mut state);

        for round in 1..num_rounds {
            self.sub_bytes(&mut state);
            self.shift_rows(&mut state);
            self.mix_columns(&mut state);
            self.add_round_key(round, &mut state);
        }

        // Final round (no MixColumns)
        self.sub_bytes(&mut state);
        self.shift_rows(&mut state);
        self.add_round_key(num_rounds, &mut state);

        let result = from_2d_array(&state);
        output.copy_from_slice(&result);
    }

    fn inverted_cipher(&mut self, buffer: &[u8], output: &mut [u8]) {
        let num_rounds = match self.size {
            AesSize::S128 => 10,
            AesSize::S192 => 12,
            AesSize::S256 => 14,
        };
        let mut output_slice = [0; AES_BLOCK_LENGTH_BYTES];
        for (i, byte) in buffer[0..AES_BLOCK_LENGTH_BYTES].iter().enumerate() {
            output_slice[i] = *byte;
        }
        let mut state = as_2d_array(&mut output_slice);
        self.add_round_key(num_rounds, &mut state);

        for round in (1..=num_rounds - 1).rev() {
            self.inv_shift_rows(&mut state);
            self.inverted_sub_bytes(&mut state);
            self.add_round_key(round, &mut state);
            self.inv_mix_columns(&mut state);
        }
        self.inv_shift_rows(&mut state);
        self.inverted_sub_bytes(&mut state);
        self.add_round_key(0, &mut state);

        output_slice = from_2d_array(&mut state);
        for (i, byte) in output_slice.iter().enumerate() {
            output[i] = *byte;
        }
    }
    /*
       Generate a new IV to be used
    */
    fn generate_initialization_vector(&mut self) {
        rand::fill(&mut self.initialization_vector);
    }

    /*
       The last 16 bytes will hold the IV
    */
    fn read_initialization_vector(&mut self, buffer: &mut [u8]) -> [u8; AES_BLOCK_LENGTH_BYTES] {
        let len = buffer.len();
        let start = len - AES_BLOCK_LENGTH_BYTES;
        let mut array = [0u8; AES_BLOCK_LENGTH_BYTES];

        for i in 0..AES_BLOCK_LENGTH_BYTES {
            array[i] = buffer[start + i];
        }
        array
    }
    /*
       Xor single block in the buffer with the initialization vector stored
       internally
    */
    fn xor_with_initialization_vector(
        &mut self,
        buffer: &mut [u8],
        initialization_vector: Option<&[u8]>,
    ) {
        let use_passed = initialization_vector.is_some();
        for i in 0..AES_BLOCK_LENGTH_BYTES {
            if use_passed {
                let vector = initialization_vector.unwrap();
                buffer[i] ^= vector[i];
            } else {
                buffer[i] ^= self.initialization_vector[i];
            }
        }
    }

    fn ecb_encrypt(&mut self, buffer: &[u8], output: &mut [u8]) {
        self.cipher(buffer, output);
    }

    fn ecb_decrypt(&mut self, buffer: &[u8], output: &mut [u8]) {
        self.inverted_cipher(buffer, output);
    }

    /*
       Encrypt/Decrypt in CBC mode (cipher block chaining)
       CBC xors each block with the previous block of plain/ciphertext

    */
    fn cbc_encrypt(&mut self, buffer: &[u8], output: &mut Vec<u8>) {
        /*
           Generate a fresh IV every encryption operation
        */
        self.generate_initialization_vector();
        /*
           Casting these just in case it goes negative on the subtraction operation, don't want wraparound or panic because of this
        */
        let input_len: i64 = buffer.len() as i64;
        let output_len: i64 = output.capacity() as i64;

        /*
           Resize if required to store the 16 byte IV as a prefix to the rest of the data
        */
        if (output_len - AES_BLOCK_LENGTH_BYTES as i64) < input_len {
            output.resize(input_len as usize + AES_BLOCK_LENGTH_BYTES, 0);
        }

        /*
           Stuff the IV right on in there
        */
        for i in 0..AES_BLOCK_LENGTH_BYTES {
            output[i] = self.initialization_vector[i];
        }

        let mut current_slice = [0u8; AES_BLOCK_LENGTH_BYTES];
        let mut output_slice = [0u8; AES_BLOCK_LENGTH_BYTES];

        let mut initialization_vector = self.initialization_vector.clone();

        for i in 0..(input_len as usize / AES_BLOCK_LENGTH_BYTES) {
            for num in 0..16 {
                current_slice[num] = buffer[i * AES_BLOCK_LENGTH_BYTES + num];
            }

            self.xor_with_initialization_vector(
                &mut current_slice,
                Some(&mut initialization_vector),
            );
            self.cipher(&current_slice, &mut output_slice);
            initialization_vector = output_slice;

            for (num, byte) in output_slice.iter().enumerate() {
                output[(i * AES_BLOCK_LENGTH_BYTES + num) + AES_BLOCK_LENGTH_BYTES /* Account for IV by offsetting index by 16 bytes */] =
                    *byte;
            }
        }
    }

    fn cbc_decrypt(&mut self, buffer: &[u8], output: &mut [u8]) {
        let mut initialization_vector = [0u8; AES_BLOCK_LENGTH_BYTES];
        /*
           Stuff the IV right on in there
        */

        for i in 0..AES_BLOCK_LENGTH_BYTES {
            initialization_vector[i] = buffer[i];
        }

        let len = buffer.len() - AES_BLOCK_LENGTH_BYTES;
        let mut current_slice = [0u8; AES_BLOCK_LENGTH_BYTES];
        let mut output_slice = [0u8; AES_BLOCK_LENGTH_BYTES];

        for i in 0..(len / AES_BLOCK_LENGTH_BYTES) {
            for num in 0..AES_BLOCK_LENGTH_BYTES {
                current_slice[num] = buffer[(i * AES_BLOCK_LENGTH_BYTES + num) + AES_BLOCK_LENGTH_BYTES/* Again, offset by the size of the IV at the beginning*/];
            }
            let next_iv = current_slice;
            self.inverted_cipher(&current_slice, &mut output_slice);
            self.xor_with_initialization_vector(&mut output_slice, Some(&initialization_vector));

            initialization_vector.copy_from_slice(&next_iv);

            for (num, byte) in output_slice.iter().enumerate() {
                output[i * AES_BLOCK_LENGTH_BYTES + num] = *byte;
            }
        }
        self.initialization_vector
            .copy_from_slice(&initialization_vector);
    }

    fn ctr_encrypt(&mut self, buffer: &[u8], output: &mut Vec<u8>) {
        /*
           Generate a fresh IV every encryption operation
        */
        let mut xor_buffer;
        /*
           Casting these just in case it goes negative on the subtraction operation, don't want wraparound or panic because of this
        */
        let input_len: i64 = buffer.len() as i64;
        let output_len: i64 = output.capacity() as i64;

        /*
           We need to treat encryption and decryption different.
           On encryption, we need to generate a new nonce to use as a counter.
           On decryption we need to extract the nonce from the prefix of the input buffer (first 16 bytes)
        */

        self.generate_initialization_vector();

        /*
           Resize if required to store the 16 byte IV as a prefix to the rest of the data
        */
        if (output_len - AES_BLOCK_LENGTH_BYTES as i64) < input_len {
            output.resize(input_len as usize + AES_BLOCK_LENGTH_BYTES, 0);
        }

        /*
           Stuff the IV right on in there
        */
        for i in 0..AES_BLOCK_LENGTH_BYTES {
            output[i] = self.initialization_vector[i];
        }
        xor_buffer = self.initialization_vector.clone();

        let mut output_slice = [0u8; AES_BLOCK_LENGTH_BYTES];

        let mut counter_index = AES_BLOCK_LENGTH_BYTES; // Counter index

        let mut counter = u128::from_be_bytes(self.initialization_vector);

        for i in 0..input_len as usize {
            if counter_index == AES_BLOCK_LENGTH_BYTES {
                self.cipher(&mut xor_buffer, &mut output_slice); // Encrypt IV as AES block
                counter += 1;
                xor_buffer = counter.to_be_bytes();
                counter_index = 0; // Reset counter
            }

            // XOR plaintext with encrypted counter

            output[i + AES_BLOCK_LENGTH_BYTES] = buffer[i] ^ output_slice[counter_index];

            counter_index += 1;
        }
    }

    fn ctr_decrypt(&mut self, buffer: &[u8], output: &mut Vec<u8>) {
        /*
           Generate a fresh IV every encryption operation
        */
        let mut xor_buffer = [0; 16];
        /*
           Casting these just in case it goes negative on the subtraction operation, don't want wraparound or panic because of this
        */
        let input_len: i64 = buffer.len() as i64;
        /*
           We need to treat encryption and decryption different.
           On encryption, we need to generate a new nonce to use as a counter.
           On decryption we need to extract the nonce from the prefix of the input buffer (first 16 bytes)
        */
        for i in 0..AES_BLOCK_LENGTH_BYTES {
            xor_buffer[i] = buffer[i];
        }
        let mut output_slice = [0u8; AES_BLOCK_LENGTH_BYTES];

        let mut counter_index = AES_BLOCK_LENGTH_BYTES; // Counter index

        let mut counter = u128::from_be_bytes(xor_buffer);

        for i in 0..input_len as usize - 16usize {
            if counter_index == AES_BLOCK_LENGTH_BYTES {
                self.cipher(&mut xor_buffer, &mut output_slice); // Encrypt IV as AES block
                counter += 1;
                xor_buffer = counter.to_be_bytes();
                counter_index = 0; // Reset counter
            }

            // XOR plaintext with encrypted counter
            output[i] = buffer[i + AES_BLOCK_LENGTH_BYTES] ^ output_slice[counter_index];

            counter_index += 1;
        }
    }
    /*
       Functions below are just for testing. I can remove them but fuggit they can stay
    */
    pub fn test_round_key(&mut self, key: &[u8], round: usize) -> bool {
        let key_size = match self.size {
            AesSize::S128 => 128,
            AesSize::S192 => 192,
            AesSize::S256 => 256,
        };
        let start = round * (key_size / 8);
        let end = start + (key_size / 8);
        let round_key = &self.round_keys[start..end];

        for i in 0..key_size / 8 {
            if key[i] != round_key[i] {
                return false;
            }
        }

        true
    }

    pub fn print_round_keys(&mut self, key: &[u8; AES_KEY_LENGTH_BYTES_MAX]) {
        self.set_key(key);
        self.key_expansion();
        let num_rounds = match self.size {
            AesSize::S128 => 10,
            AesSize::S192 => 12,
            AesSize::S256 => 14,
        };
        for i in 0..=num_rounds {
            let start = i * 16;
            let end = start + 16;

            println!(
                "round {} round key: {:02x?}",
                i,
                &self.round_keys[start..end]
            );
        }
    }
}

impl Encryption for AESContext {
    fn initialize_context(&mut self) {
        self.initialize_context();
    }

    fn encrypt(&mut self, input: &mut Vec<u8>, output: &mut Vec<u8>) {
        let input_cap = input.len();
        /*
           Ensure input is block size aligned
        */
        if input_cap % AES_BLOCK_LENGTH_BYTES != 0 {
            let diff = (input_cap + AES_BLOCK_LENGTH_BYTES) % AES_BLOCK_LENGTH_BYTES;
            for _ in 0..(AES_BLOCK_LENGTH_BYTES - diff) {
                input.push(0);
            }
        }
        match self.mode {
            AesMode::CBC => {
                self.cbc_encrypt(input, output);
            }
            AesMode::ECB => {
                self.ecb_encrypt(input, output);
            }
            AesMode::CTR => {
                self.ctr_encrypt(input, output);
            }
        }
    }

    fn decrypt(&mut self, input: &mut Vec<u8>, output: &mut Vec<u8>) {
        let input_size = input.len();
        let output_size = output.len();

        if input_size > output_size {
            output.resize(input_size - AES_BLOCK_LENGTH_BYTES, 0); // Shave off the IV from the input length
        }
        match self.mode {
            AesMode::CBC => {
                self.cbc_decrypt(input, output);
            }
            AesMode::ECB => {
                self.ecb_decrypt(input, output);
            }
            AesMode::CTR => {
                self.ctr_decrypt(input, output);
            }
        }
    }

    fn set_key(&mut self, key: &[u8]) {
        for (index, byte) in key.iter().enumerate() {
            self.key[index] = *byte;
        }
        self.key_expansion();
    }
}
