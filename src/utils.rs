use std::time::{SystemTime, UNIX_EPOCH};

use aes::Aes256;
use block_modes::block_padding::Pkcs7;
use block_modes::Cbc;
use rand::{OsRng, Rng};

pub type Aes256Cbc = Cbc<Aes256, Pkcs7>;

static ALPH: [char; 64] = [
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
    't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L',
    'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '-', '_',
];
static ALPH_32: [char; 32] = [
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'j', 'k', 'n', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
    'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
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

/// Generate simple string-id [0-9a-z]
pub fn str_id_32(len: usize) -> String {
    let mut output = String::with_capacity(len);

    let mut rng = OsRng::new().unwrap();
    for _ in 0..len {
        let rd: u8 = rng.gen();
        output.push(ALPH_32[(rd & 31) as usize]);
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

// --- Tests ---
#[cfg(test)]
mod tests {
    use utils;

    #[test]
    fn uid() {
        assert!(utils::uid() != utils::uid());
        assert!(utils::uid().len() == 12);
    }

    #[test]
    fn gen_pass() {
        assert!(utils::gen_pass(10).len() == 10);
    }

    #[test]
    fn nid() {
        assert!(utils::nid() != utils::nid());
    }
}
