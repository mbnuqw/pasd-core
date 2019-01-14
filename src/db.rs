use std::collections::HashMap;
use std::os::unix::fs::OpenOptionsExt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, prelude::*};
use std::path::Path;

use block_cipher_trait::generic_array::typenum::consts::U16;
use block_cipher_trait::generic_array::GenericArray;
use block_modes::BlockMode;
use msgpack;
use scrypt::{scrypt, ScryptParams};
use sha2::{Digest, Sha256};

use config::Config;
use errors::Error;
use key::{Key, KeyInfo, KeyType, Passwords};
use secret::{AddSecretArgs, Secret, SecretInfo, SecretType};
use utils::{self, Aes256Cbc};

static DB_VERSION: u8 = 0x00;

static OUTER_SCRYPT_LOG2_N: u8 = 15;
static OUTER_SCRYPT_R: u32 = 16;
static INNER_SCRYPT_LOG2_N: u8 = 15;
static INNER_SCRYPT_R: u32 = 16;

/// Central struct that keeps secrets along with
/// some additional info.
#[derive(Debug, Deserialize, Serialize)]
pub struct DB {
    #[serde(skip)]
    path: Option<String>,
    #[serde(skip)]
    key: Option<String>,
    #[serde(skip)]
    backups_path: Option<String>,
    pub keys: Vec<Key>,
    pub secrets: Vec<Secret>,
}

impl DB {
    /// Initialize database.
    pub fn new(conf: &Config) -> DB {
        DB {
            path: conf.db_path.clone(),
            key: conf.db_key.clone(),
            backups_path: conf.backups_path.clone(),
            keys: vec![],
            secrets: vec![],
        }
    }

    /// Load secure data
    pub fn load(&mut self) -> Result<(), Error> {
        println!(" → Loading DB");
        let mut db_file = self.open("r")?;
        if let Ok(meta) = db_file.metadata() {
            if meta.len() == 0 {
                return Ok(());
            }
        }

        // Read and validate file
        let mut sig = [0u8; 3];
        let mut data = Vec::with_capacity(1024);
        db_file.read(&mut sig)?;
        if sig[0] != 0x00 || sig[1] != sig[2] {
            return Err(Error::InvalidDBFormat);
        }
        if sig[1] != DB_VERSION {
            // Handle format change
            return Err(Error::InvalidDBFormat);
        }
        db_file.read_to_end(&mut data)?;
        println!(" →   File was read and verifyed, len: {:?}, sig: {:?}", data.len(), sig);

        // Decrypt
        let outer_key = self.get_outer_key()?;
        let outer_iv = self.get_outer_iv()?;
        let cipher = match Aes256Cbc::new_var(&outer_key, &outer_iv) {
            Ok(c) => c,
            Err(_) => return Err(Error::IncorrectOuterKey),
        };
        let decrypted = utils::decrypt(data, cipher)?;

        let db: DB = msgpack::from_slice(&decrypted)?;
        self.keys = db.keys;
        self.secrets = db.secrets;
        println!(" →   DB successfully loaded");

        Ok(())
    }

    /// Check if db is ready
    pub fn should_be_ready(&self) -> Result<(), Error> {
        if self.path.is_none() {
            return Err(Error::IncorrectConf);
        }
        Ok(())
    }

    /// Unload secure data
    pub fn unload(&mut self) {
        println!(" → Unloading DB");
        self.keys.clear();
        self.secrets.clear();
        println!(" →   DB unloaded\n");
    }

    /// Save db
    pub fn save(&mut self) -> Result<(), Error> {
        println!(" → Saving DB");
        println!(" {:?}", self);
        let mut db_file = self.open("rw")?;

        // Serialize DB
        let data = msgpack::to_vec(&self)?;
        println!(" →   DB serialized, len: {:?}", data.len());

        // Encrypt
        let outer_key = self.get_outer_key()?;
        let outer_iv = self.get_outer_iv()?;
        let cipher = match Aes256Cbc::new_var(&outer_key, &outer_iv) {
            Ok(c) => c,
            Err(_) => return Err(Error::IncorrectOuterKey),
        };
        let encrypted = utils::encrypt(data, cipher)?;
        println!(" →   DB encrypted, len: {:?}", encrypted.len());

        // Reset and write new content
        let sig: [u8; 3] = [0x00, DB_VERSION, DB_VERSION];
        db_file.set_len(0)?;
        db_file.write_all(&sig)?;
        db_file.write_all(&encrypted)?;
        println!(" →   DB writed with sig: {:?}", sig);

        // Backup
        if let Some(ref b) = self.backups_path {
            let backup_name = "pasd_backup";
            let backup_dir = Path::new(b);
            let mut backup_file = OpenOptions::new()
                .create(true)
                .write(true)
                .mode(0o666)
                .open(backup_dir.join(backup_name))?;
            backup_file.set_len(0)?;
            backup_file.write_all(&sig)?;
            backup_file.write_all(&encrypted)?;
        }

        Ok(())
    }

    /// Try to open database file
    pub fn open(&self, opts: &str) -> Result<File, Error> {
        let path = match self.path {
            Some(ref p) => p,
            None => return Err(Error::IncorrectConf),
        };
        let db_path = Path::new(path);
        let r = opts.contains('r');
        let w = opts.contains('w');

        match fs::OpenOptions::new().read(r).write(w).open(db_path) {
            Ok(v) => Ok(v),
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => Ok(self.create_db()?),
            Err(e) => return Err(Error::IO(e)),
        }
    }

    /// Create new database file
    pub fn create_db(&self) -> Result<File, Error> {
        // Create dir if not exists yet
        let path = match self.path {
            Some(ref p) => p,
            None => return Err(Error::IncorrectConf),
        };
        let db_path = Path::new(&path);
        if let Some(parent) = db_path.parent() {
            if !parent.exists() {
                fs::create_dir_all(&parent)?;
            }
        }

        // Write file
        let mut db_file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(db_path)?;
        db_file.write_all(&[])?;

        Ok(db_file)
    }

    /// Add new key to this database
    pub fn add_key(&mut self, key: Key, passwords: Passwords) -> Result<(), Error> {
        self.should_be_ready()?;

        // Load DB
        self.load()?;

        // Check if key with this name is not existed
        if !self.keys.iter().find(|k| k.name == key.name).is_none() {
            return Err(Error::Duplicate);
        }

        // Validate all keys
        for key in self.keys.iter() {
            if !key.validate(&passwords) {
                return Err(Error::InvalidKey);
            }
        }

        // Decrypt secrets, update keys, encrypt secrets
        let secret_values = self.decrypt_all_secrets(&passwords)?;
        self.keys.push(key);
        self.encrypt_all_secrets(secret_values, &passwords)?;

        self.save()?;

        // Unload DB
        self.unload();

        Ok(())
    }

    /// Add new secret to this database
    pub fn add_secret(&mut self, args: AddSecretArgs, passwords: Passwords) -> Result<(), Error> {
        self.should_be_ready()?;

        // Load DB
        self.load()?;

        // Get all key groups
        let key_groups = self.get_key_groups();

        let secret = match key_groups.len() {
            // There are no keys, hence store plain value
            0 => Secret::from_args(args, None)?,

            // Multiple keys - create ciphers and encrypt!
            _ => {
                // Validate all keys
                for key in self.keys.iter() {
                    if !key.validate(&passwords) {
                        return Err(Error::InvalidKey);
                    }
                }

                // Get ciphers, encrypt secret and add to db
                let ciphers = DB::get_ciphers(&self.keys, &key_groups, &passwords)?;
                Secret::from_args(args, Some(ciphers))?
            }
        };

        self.secrets.push(secret);
        self.save()?;

        // Unload DB
        self.unload();

        Ok(())
    }

    /// Remove key
    pub fn rm_key(&mut self, key_name: &str, passwords: Passwords) -> Result<(), Error> {
        self.should_be_ready()?;

        // Load DB
        self.load()?;

        // Check if key with this name is exists
        let name = key_name.to_string();
        let key_index = match self.keys.iter().position(|k| k.name == name) {
            Some(i) => i,
            None => return Err(Error::NotFound),
        };

        // Validate all keys
        for key in self.keys.iter() {
            if !key.validate(&passwords) {
                return Err(Error::InvalidKey);
            }
        }

        // Decrypt secrets, update keys, encrypt secrets
        let secret_values = self.decrypt_all_secrets(&passwords)?;
        self.keys.remove(key_index);
        self.encrypt_all_secrets(secret_values, &passwords)?;

        self.save()?;

        // Unload DB
        self.unload();

        Ok(())
    }

    /// Remove secret
    pub fn rm_secret(&mut self, secret_name: &str, passwords: Passwords) -> Result<(), Error> {
        self.should_be_ready()?;

        // Load DB
        self.load()?;

        // Check if secret with this name is existed
        let secret_index = match self.secrets.iter().position(|k| k.name == secret_name) {
            Some(i) => i,
            None => return Err(Error::NotFound),
        };

        // Validate all keys
        for key in self.keys.iter() {
            if !key.validate(&passwords) {
                return Err(Error::InvalidKey);
            }
        }

        // Remove secret and save
        self.secrets.remove(secret_index);
        self.save()?;

        // Unload DB
        self.unload();

        Ok(())
    }

    /// List all keys
    pub fn list_keys(&mut self) -> Result<Vec<KeyInfo>, Error> {
        self.should_be_ready()?;

        self.load()?;
        let keys = self.keys.iter().map(|k| k.into()).collect();
        self.unload();

        Ok(keys)
    }

    /// List all secrets
    pub fn list_secrets(&mut self) -> Result<Vec<SecretInfo>, Error> {
        self.should_be_ready()?;

        self.load()?;
        let secrets = self.secrets.iter().map(|s| s.into()).collect();
        self.unload();

        Ok(secrets)
    }

    /// Find, decrypt and return secret value with type
    pub fn get_secret(
        &mut self,
        query: Vec<String>,
        passwords: Passwords,
    ) -> Result<(Vec<u8>, SecretType), Error> {
        self.should_be_ready()?;

        // Load DB
        self.load()?;

        let value_with_type = {
            // Try to find secret
            let secret = self.find_secret(query)?;
            let secret_type = secret.secret_type;

            if self.keys.len() == 0 {
                let value = secret.get_plain()?;
                return Ok((value, secret_type));
            }

            // Find available key group for decrypting
            let key_groups = self.get_key_groups();
            let valid_group = key_groups
                .iter()
                .find(|(_, keys_ids)| {
                    // Retrive key by id and validate it
                    match self.keys.iter().find(|k| keys_ids.contains(&k.id)) {
                        Some(key) => key.validate(&passwords),
                        None => false,
                    }
                })
                .ok_or(Error::InvalidKey)?;

            // Retrieve secret value with its type
            let group_name = valid_group.0.clone();
            let group_keys = valid_group.1.clone();
            let cipher = DB::get_group_cipher(&self.keys.clone(), &group_keys, &passwords)?;
            let value = secret.decrypt(group_name, cipher)?.clone();
            (value, secret_type)
        };

        // Unload DB
        self.unload();

        Ok(value_with_type)
    }

    /// Try to find secret by name/url/login
    fn find_secret(&self, args: Vec<String>) -> Result<&Secret, Error> {
        let maybe_secret = self.secrets.iter().find(|secret| {
            // Check if all arguments matched
            args.iter().all(|arg| {
                let norm_arg = arg.to_lowercase();

                // Name
                if secret.name.to_lowercase().find(&norm_arg).is_some() {
                    return true;
                }

                // Url
                if let Some(ref url) = secret.url {
                    if url.to_lowercase().find(&norm_arg).is_some() {
                        return true
                    }
                }

                // Login
                if let Some(ref login) = secret.login {
                    if login.to_lowercase().find(&norm_arg).is_some() {
                        return true;
                    }
                }

                return false;
            })
        });

        match maybe_secret {
            Some(s) => Ok(s),
            None => Err(Error::NotFound),
        }
    }

    /// Get outer iv value
    fn get_outer_iv(&self) -> Result<GenericArray<u8, U16>, Error> {
        let key = match self.key {
            Some(ref k) => k.as_bytes(),
            None => return Err(Error::IncorrectConf),
        };

        // Generate iv
        let mut hasher = Sha256::new();
        hasher.input(key);
        let hashed_key = hasher.result();
        let (hashed_iv, _) = hashed_key.as_slice().split_at(16);

        Ok(*GenericArray::from_slice(hashed_iv))
    }

    /// Get outer db key (outer)
    fn get_outer_key(&self) -> Result<[u8; 32], Error> {
        let key = match self.key {
            Some(ref k) => k.as_bytes(),
            None => return Err(Error::IncorrectConf),
        };

        // Generate salt
        let mut hasher_1 = Sha256::new();
        let mut hasher_2 = Sha256::new();
        hasher_1.input(key);
        let hashed_key_1 = hasher_1.result();
        hasher_2.input(hashed_key_1);
        let hashed_key = hasher_2.result();

        // Derive key
        let mut derived_key = [0u8; 32];
        let scrypt_params = ScryptParams::new(OUTER_SCRYPT_LOG2_N, OUTER_SCRYPT_R, 1)?;
        scrypt(&key, &hashed_key, &scrypt_params, &mut derived_key)?;
        // pbkdf2::<Hmac<Sha256>>(&key, &hashed_key, OUTER_C, &mut derived_key);

        Ok(derived_key)
    }

    /// Get hashed key and iv from provided secret
    fn get_inner_key_iv(group_key: Vec<u8>) -> Result<([u8; 32], GenericArray<u8, U16>), Error> {
        // Get hashed parts
        let mut hasher = Sha256::new();
        hasher.input(group_key.clone());
        let garr = hasher.result();
        let (h_iv, h_salt) = garr.as_slice().split_at(16);

        // Key
        let mut key = [0u8; 32];
        let scrypt_params = ScryptParams::new(INNER_SCRYPT_LOG2_N, INNER_SCRYPT_R, 1)?;
        scrypt(&group_key, &h_salt[..4], &scrypt_params, &mut key)?;
        // pbkdf2::<Hmac<Sha256>>(&group_key, &h_salt[..4], INNER_C, &mut key);

        // IV
        let iv = *GenericArray::from_slice(h_iv);

        Ok((key, iv))
    }

    /// Get ciphers by keys groups
    fn get_ciphers(
        keys: &Vec<Key>,
        key_groups: &HashMap<String, Vec<String>>,
        passwords: &Passwords,
    ) -> Result<HashMap<String, Aes256Cbc>, Error> {
        let mut ciphers = HashMap::with_capacity(3);

        for (g, keys_ids) in key_groups.iter() {
            let c = DB::get_group_cipher(keys, keys_ids, passwords)?;
            ciphers.insert(g.clone(), c);
        }

        Ok(ciphers)
    }

    /// Get cipher from group of keys
    fn get_group_cipher(
        keys: &Vec<Key>,
        keys_ids: &Vec<String>,
        passwords: &Passwords,
    ) -> Result<Aes256Cbc, Error> {
        let mut group_secret: Vec<u8> = Vec::with_capacity(1024);

        for key_id in keys_ids.iter() {
            let key = match keys.iter().find(|k| k.id == *key_id) {
                Some(k) => k,
                None => return Err(Error::InvalidKey),
            };

            match key.key_type {
                KeyType::Text => match passwords.iter().find(|(kn, _)| **kn == key.name) {
                    Some((_, kv)) => group_secret.append(&mut kv.clone().into_bytes()),
                    None => return Err(Error::InvalidKey),
                },
                KeyType::File => {
                    // Read file, find hash and use it as value
                    let path = key.addr.clone().ok_or(Error::InvalidKey)?;
                    let file_data = fs::read(path)?;
                    let mut hasher = Sha256::new();
                    hasher.input(file_data);
                    let hr = hasher.result();
                    let mut h = hr.as_slice();
                    group_secret.append(&mut Vec::from(h).clone());
                }
            }
        }

        let (key, iv) = DB::get_inner_key_iv(group_secret)?;
        Ok(Aes256Cbc::new_var(&key, &iv)?)
    }

    /// Decrypt all secrets and return values
    fn decrypt_all_secrets(&mut self, passwords: &Passwords) -> Result<Vec<Vec<u8>>, Error> {
        // Get first keys group
        let key_groups = self.get_key_groups();
        let mut values = Vec::with_capacity(self.secrets.len());

        if key_groups.len() > 0 {
            let group = match key_groups.into_iter().next() {
                Some(g) => g,
                None => return Err(Error::NotEnoughKeys),
            };

            for secret in self.secrets.iter_mut() {
                let group_keys = group.1.clone();
                let cipher = DB::get_group_cipher(&self.keys.clone(), &group_keys, passwords)?;
                values.push(secret.decrypt(group.0.clone(), cipher)?);
            }
        } else {
            for secret in self.secrets.iter_mut() {
                values.push(secret.get_plain()?)
            }
        }

        Ok(values)
    }

    /// Update values of all secrets with provided
    /// values vector
    fn encrypt_all_secrets(
        &mut self,
        values: Vec<Vec<u8>>,
        passwords: &Passwords,
    ) -> Result<(), Error> {
        let key_groups = self.get_key_groups();

        if key_groups.len() > 0 {
            for (s, v) in self.secrets.iter_mut().zip(values) {
                let ciphers = DB::get_ciphers(&self.keys.clone(), &key_groups, &passwords)?;
                s.encrypt(&v, ciphers)?;
            }
        } else {
            self.secrets
                .iter_mut()
                .zip(values)
                .for_each(|(s, v)| s.set_plain(v.clone()));
        }

        Ok(())
    }

    /// Get all key groups
    fn get_key_groups(&self) -> HashMap<String, Vec<String>> {
        let mut groups = HashMap::with_capacity(3);

        for k in self.keys.iter() {
            if !groups.contains_key(&k.group) {
                groups.insert(k.group.clone(), vec![k.id.clone()]);
                continue;
            }
            match groups.get_mut(&k.group) {
                Some(g) => g.push(k.id.clone()),
                None => (),
            }
        }

        groups
    }
}
