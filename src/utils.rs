use std::time::{SystemTime, UNIX_EPOCH};

use aes::Aes256;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use rand::{OsRng, Rng};

use errors::Error;

pub type Aes256Cbc = Cbc<Aes256, Pkcs7>;

static ALPH: [char; 64] = [
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
    't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L',
    'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '-', '_',
];

/// Generate simple uid string
pub fn uid() -> String {
    // Get time part
    let unix_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let mut ns: u32 = unix_time.subsec_nanos();

    // Get rand part
    let mut rng = OsRng::new().unwrap();
    let mut rd: u64 = rng.gen();

    // Result string
    let mut output = String::with_capacity(12);

    // Rand part
    for _ in 0..7 {
        output.push(ALPH[(rd & 63) as usize]);
        rd >>= 6;
    }

    // Time part
    for _ in 0..5 {
        output.push(ALPH[(ns & 63) as usize]);
        ns >>= 6;
    }

    return output;
}

/// Generate random string.
pub fn gen_pass(len: usize) -> String {
    let mut output = String::with_capacity(len);

    let mut rng = OsRng::new().unwrap();
    for _ in 0..len {
        let rd: u8 = rng.gen();
        output.push(ALPH[(rd & 63) as usize]);
    }

    return output;
}

/// Generate numerical id
pub fn nid() -> u64 {
    // Get time part
    let unix_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let ns: u32 = unix_time.subsec_nanos();

    // Get rand part
    let mut rng = OsRng::new().unwrap();
    let rd: u32 = rng.gen();

    // Result
    ((rd as u64) << 32) | ns as u64
}

/// Encrypt bytes
pub fn encrypt(mut input: Vec<u8>, mut cipher: Aes256Cbc) -> Result<Vec<u8>, Error> {
    let mut encrypted: Vec<u8> = Vec::with_capacity(2048);

    for mut chunk in input.chunks_mut(16) {
        // Not-full last chunk
        if chunk.len() < 16 {
            let mut buffer = [0u8; 32];
            buffer[0..chunk.len()].copy_from_slice(&chunk);
            let the_last = cipher.encrypt(&mut buffer, chunk.len())?;
            encrypted.extend_from_slice(the_last);
            break;
        }

        // Full chunks
        cipher.encrypt(&mut chunk, 16)?;
        encrypted.extend_from_slice(&chunk);
    }

    Ok(encrypted)
}

/// Decrypt bytes
pub fn decrypt(mut input: Vec<u8>, mut cipher: Aes256Cbc) -> Result<Vec<u8>, Error> {
    let mut decrypted = Vec::with_capacity(2048);
    let last_i = input.len() / 16 - 1;

    for (i, mut chunk) in input.chunks_mut(16).enumerate() {
        // Last chunk
        if i == last_i {
            let the_last = cipher.decrypt(&mut chunk)?;
            decrypted.extend_from_slice(the_last);
            break;
        }

        cipher.decrypt(&mut chunk)?;
        decrypted.extend_from_slice(&chunk);
    }

    Ok(decrypted)
}

// -----------------------------
// --- --- --- Tests --- --- ---
// -----------------------------
#[cfg(test)]
mod tests {
    use block_cipher_trait::generic_array::GenericArray;
    use block_modes::BlockMode;
    use utils::*;

    #[test]
    fn encryption() {
        let key = [0u8; 32];
        let iv = *GenericArray::from_slice(&[0u8; 16]);
        let cipher = Aes256Cbc::new_var(&key, &iv).unwrap();

        let input = "Ok, just test string, nothing special...";
        let enc = encrypt(Vec::from(input), cipher).unwrap();
        let expected: Vec<u8> = vec![
            69, 202, 218, 247, 150, 136, 226, 229, 109, 48, 187, 61, 12, 132, 72, 235, 24, 183,
            214, 13, 119, 24, 138, 20, 147, 13, 195, 15, 241, 56, 50, 111, 78, 134, 4, 160, 217,
            49, 130, 113, 151, 222, 164, 198, 138, 20, 58, 71,
        ];

        assert_eq!(enc, expected);
    }

    #[test]
    fn encryption_without_padding() {
        let key = [0u8; 32];
        let iv = *GenericArray::from_slice(&[0u8; 16]);
        let cipher = Aes256Cbc::new_var(&key, &iv).unwrap();

        let input = "Ok, this is 32-len test string..";
        let enc = encrypt(Vec::from(input), cipher).unwrap();
        let expected: Vec<u8> = vec![
            50, 221, 228, 118, 235, 92, 213, 75, 246, 247, 143, 174, 141, 73, 67, 80, 250, 27, 152,
            211, 101, 57, 91, 38, 155, 128, 166, 83, 191, 202, 188, 66,
        ];

        assert_eq!(enc, expected);
    }

    #[test]
    fn dectyption() {
        let key = [0u8; 32];
        let iv = *GenericArray::from_slice(&[0u8; 16]);
        let cipher = Aes256Cbc::new_var(&key, &iv).unwrap();

        let input: Vec<u8> = vec![
            69, 202, 218, 247, 150, 136, 226, 229, 109, 48, 187, 61, 12, 132, 72, 235, 24, 183,
            214, 13, 119, 24, 138, 20, 147, 13, 195, 15, 241, 56, 50, 111, 78, 134, 4, 160, 217,
            49, 130, 113, 151, 222, 164, 198, 138, 20, 58, 71,
        ];
        let dec = decrypt(Vec::from(input), cipher).unwrap();
        let expected = "Ok, just test string, nothing special...";

        assert_eq!(String::from_utf8_lossy(&dec), expected);
    }
}
