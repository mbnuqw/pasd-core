use std::collections::HashMap;
use std::fs;
use sha2::{Sha256, Digest};
use chrono::Local;

use utils;
use errors::Error;

pub type Passwords = HashMap<String, String>;

/// Key types
/// 
/// Text - password key
/// File - hash of file's content
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyType {
    Text,
    File,
}

/// Arguments for adding new key
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AddKeyArgs {
    #[serde(rename = "type")]
    pub key_type: KeyType,
    pub name: String,
    pub group: Option<String>,
    pub value: String,
    pub passwords: Passwords,
}

/// Key info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KeyInfo {
    #[serde(rename = "type")]
    pub key_type: KeyType,
    pub name: String,
    pub group: String,
    pub addr: Option<String>,
    pub date: i64,
}

/// Key for opening database
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Key {
    #[serde(rename = "type")]
    pub key_type: KeyType,
    pub id: String,
    pub hs: Vec<u8>,
    pub name: String,
    pub group: String,
    pub addr: Option<String>,
    pub date: i64,
}

impl Key {
    /// Create key from arguments object
    pub fn from_args(args: AddKeyArgs) -> Result<Self, Error> {
        // Get key value hashsum
        let hs = match args.key_type {
            KeyType::Text => {
                let mut hasher = Sha256::new();
                hasher.input(args.value.clone());
                Vec::from(hasher.result().as_slice())
            },
            KeyType::File => {
                let file_data = fs::read(args.value.clone())?;
                let mut hasher_1 = Sha256::new();
                hasher_1.input(file_data);
                let mut hasher_2 = Sha256::new();
                hasher_2.input(hasher_1.result());
                Vec::from(hasher_2.result().as_slice())
            },
        };

        // Get file-key addr
        let addr = match args.key_type {
            KeyType::File => Some(args.value),
            _ => None,
        };

        // Get key group
        let group = match args.group {
            Some(g) => g,
            None => args.name.clone(),
        };

        // Return key obj
        Ok(Key {
            key_type: args.key_type,
            id: utils::uid(),
            hs: hs,
            name: args.name,
            group: group,
            addr: addr,
            date: Local::now().timestamp(),
        })
    }

    /// Validate key.
    /// Get key value, find hashsum of it and compare with stored
    /// hashsum-value. If something goes wrong, return false.
    pub fn validate(&self, passwords: &Passwords) -> bool {
        match self.key_type {
            KeyType::Text => {
                // Check from 'passwords' arg
                let hs = self.hs.clone();
                let kval = match passwords.get(&self.name) {
                    Some(v) => v,
                    None => return false,
                };

                let mut hasher = Sha256::new();
                hasher.input(kval);
                let test_hs_arr = hasher.result();
                let test_hs = test_hs_arr.as_slice();

                return hs == test_hs;
            }
            KeyType::File => {
                // Read file
                let hs = self.hs.clone();
                let path = match self.addr {
                    Some(ref a) => a,
                    None => return false,
                };
                let file_data = match fs::read(path) {
                    Ok(data) => data,
                    Err(_) => return false,
                };

                let mut hasher_1 = Sha256::new();
                hasher_1.input(file_data);
                let mut hasher_2 = Sha256::new();
                hasher_2.input(hasher_1.result());
                let test_hs_arr = hasher_2.result();
                let test_hs = test_hs_arr.as_slice();

                // Check file's hash
                return hs == test_hs;
            }
        }
    }
}

impl<'a> From<&'a Key> for KeyInfo {
    fn from(key: &Key) -> Self {
        KeyInfo {
            key_type: key.key_type.clone(),
            name: key.name.clone(),
            group: key.group.clone(),
            addr: key.addr.clone(),
            date: key.date,
        }
    }
}

// -----------------------------
// --- --- --- Tests --- --- ---
// -----------------------------
#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use key::*;

    #[test]
    fn creating_new_key_from_args() {
        // define arguments
        let args = AddKeyArgs {
            key_type: KeyType::Text,
            name: "JustKey".to_string(),
            group: None,
            value: "Passwordf".to_string(),
            passwords: HashMap::new(),
        };

        // create key
        let key = Key::from_args(args).unwrap();

        // check fields
        assert_eq!(key.key_type, KeyType::Text);
        assert_eq!(key.name, "JustKey".to_string());
        assert_eq!(key.group, "JustKey".to_string());
        let mut hasher = Sha256::new();
        hasher.input("Passwordf");
        let hs = Vec::from(hasher.result().as_slice());
        assert_eq!(key.hs, hs);
    }
}