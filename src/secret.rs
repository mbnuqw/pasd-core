use std::collections::HashMap;
use std::fs::File;
use std::io::prelude::*;

use chrono::Local;
use block_modes::BlockMode;

use errors::Error;
use key::Passwords;
use utils::Aes256Cbc;

#[derive(Debug, Copy, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretType {
    Text,
    File,
}

/// Secret value
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecretValue {
    pub group: String,
    pub value: Vec<u8>,
}

/// Arguments for adding new secret
#[derive(Debug, Deserialize)]
pub struct AddSecretArgs {
    #[serde(rename = "type")]
    pub secret_type: SecretType,
    pub name: String,
    pub value: String,
    pub url: Option<String>,
    pub login: Option<String>,
    pub passwords: Passwords,
}

/// Secret info for lists output
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecretInfo {
    #[serde(rename = "type")]
    pub secret_type: SecretType,
    pub name: String,
    pub url: Option<String>,
    pub login: Option<String>,
    pub date: i64,
}

/// Pasd secret struct
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Secret {
    #[serde(rename = "type")]
    pub secret_type: SecretType,
    pub name: String,
    pub url: Option<String>,
    pub login: Option<String>,
    value: Option<Vec<u8>>,
    pub values: Vec<SecretValue>,
    pub date: i64,
}

impl Secret {
    /// Create new secret using provided cipher
    pub fn new(
        name: String,
        secret_type: SecretType,
        value: &[u8],
        url: Option<String>,
        login: Option<String>,
        ciphers: HashMap<String, Aes256Cbc>,
    ) -> Result<Self, Error> {
        // Read file content
        let value = match secret_type {
            SecretType::File => {
                let mut file = File::open(String::from_utf8_lossy(value).into_owned())?;
                let mut file_value = Vec::with_capacity(2048);
                file.read_to_end(&mut file_value)?;
                file_value
            },
            SecretType::Text => Vec::from(value),
        };

        let mut values = Vec::with_capacity(3);
        for (g, cipher) in ciphers {
            values.push(SecretValue {
                group: g.clone(),
                value: cipher.encrypt_vec(&value.clone()),
            });
        }

        Ok(Secret {
            secret_type: secret_type,
            name: name,
            url: url,
            login: login,
            value: None,
            values: values,
            date: Local::now().timestamp(),
        })
    }

    /// Create secret from arguments object
    pub fn from_args(
        args: AddSecretArgs,
        ciphers: Option<HashMap<String, Aes256Cbc>>,
    ) -> Result<Self, Error> {
        // Get provided value of secret
        let value = match args.secret_type {
            // Read file content
            SecretType::File => {
                let mut file = File::open(args.value)?;
                let mut file_value = Vec::with_capacity(2048);
                file.read_to_end(&mut file_value)?;
                file_value
            },
            // or just use text value
            SecretType::Text => Vec::from(args.value),
        };

        let mut plain = None;
        let mut values = Vec::with_capacity(3);
        if let Some(ciphers) = ciphers {
            for (g, cipher) in ciphers {
                values.push(SecretValue {
                    group: g.clone(),
                    value: cipher.encrypt_vec(&value.clone()),
                });
            }
        } else {
            plain = Some(value);
        }

        let secret = Secret {
            secret_type: args.secret_type,
            name: args.name,
            url: args.url,
            login: args.login,
            value: plain,
            values: values,
            date: Local::now().timestamp(),
        };

        Ok(secret)
    }

    /// Get decrypted value of secret
    pub fn decrypt(&self, group_name: String, cipher: Aes256Cbc) -> Result<Vec<u8>, Error> {
        let value = match self.values.iter().find(|v| v.group == group_name) {
            Some(v) => v,
            None => return Err(Error::InvalidKey),
        };

        Ok(cipher.decrypt_vec(&value.value.clone())?)
    }

    /// Encrypt new secret value
    pub fn encrypt(
        &mut self,
        value: &Vec<u8>,
        ciphers: HashMap<String, Aes256Cbc>,
    ) -> Result<(), Error> {
        let mut values = Vec::with_capacity(3);

        // Remove plain value
        if self.value.is_some() {
            self.value = None
        }

        for (g, cipher) in ciphers {
            values.push(SecretValue {
                group: g.clone(),
                value: cipher.encrypt_vec(&value.clone()),
            });
        }

        self.values = values;

        Ok(())
    }

    /// Try to get plain value
    pub fn get_plain(&self) -> Result<Vec<u8>, Error> {
        match self.value {
            Some(ref v) => return Ok(v.clone()),
            None => return Err(Error::NotFound),
        }
    }

    /// Set plain value
    pub fn set_plain(&mut self, value: Vec<u8>) {
        self.value = Some(value);
        self.values = vec![];
    }
}

impl<'a> From<&'a Secret> for SecretInfo {
    fn from(s: &Secret) -> Self {
        SecretInfo {
            secret_type: s.secret_type.clone(),
            name: s.name.clone(),
            url: s.url.clone(),
            login: s.login.clone(),
            date: s.date,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use block_modes::BlockMode;
    use secret::*;

    #[test]
    fn creating_new_secret() {
        // define two ciphers
        let key_1 = [1u8; 32];
        let cipher_1 = Aes256Cbc::new_var(&key_1, &[1u8; 16]).unwrap();

        let key_2 = [2u8; 32];
        let cipher_2 = Aes256Cbc::new_var(&key_2, &[2u8; 16]).unwrap();

        let mut ciphers = HashMap::with_capacity(2);
        ciphers.insert("Uno".to_string(), cipher_1);
        ciphers.insert("Duo".to_string(), cipher_2);

        // create new secret
        let secret = Secret::new(
            "Ok, secret".to_string(),
            SecretType::Text,
            "This is value".as_bytes(),
            None,
            None,
            ciphers,
        ).unwrap();

        // check fields
        assert_eq!(secret.name, "Ok, secret".to_string());
        assert_eq!(secret.secret_type, SecretType::Text);
        assert_eq!(secret.url, None);
        assert_eq!(secret.login, None);
        assert_eq!(secret.values.len(), 2);

        let key_1a = [1u8; 32];
        let cipher_1a = Aes256Cbc::new_var(&key_1a, &[1u8; 16]).unwrap();
        let value = secret.decrypt("Uno".to_string(), cipher_1a).unwrap();
        assert_eq!(value, Vec::from("This is value"));
    }
}