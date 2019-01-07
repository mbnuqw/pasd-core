use errors::Error;
use serde::de::DeserializeOwned;
use std::os::unix::fs::OpenOptionsExt;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, prelude::*};
use std::path::{Path, PathBuf};
use toml;

/// Main config struct
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub db_path: Option<String>,
    pub db_key: Option<String>,
    pub ipc_socket_path: Option<String>,
}

impl Config {
    /// Try to load config. If config not found, create it.
    pub fn load() -> Config {
        // Get dirname
        let dir_path = Config::reveal_dir_path("pasd");

        // Read it
        match Config::read(dir_path.to_owned(), "config.toml") {
            Ok(conf) => conf,
            Err(_) => Config { db_path: None, db_key: None, ipc_socket_path: None },
        }
    }

    /// Reveal config dir path for current platform.
    fn reveal_dir_path(name: &str) -> PathBuf {
        let home_path_str = env::var("HOME").expect("I thought you have HOME var...");
        if home_path_str == "/root" {
            return Path::new("/etc/pasd").to_path_buf()
        }
        let home_path = Path::new(&home_path_str);
        let conf_path = match env::var("XDG_CONFIG_HOME") {
            Ok(v) => Path::new(&v).join(Path::new(name)),
            Err(_) => home_path.join(Path::new(&[".config/", name].concat())),
        };

        return conf_path;
    }

    /// Try to read config file
    fn read<T: DeserializeOwned>(dir_path: PathBuf, name: &str) -> Result<T, Error> {
        // Try to open and read file
        let mut conf_file = match File::open(dir_path.join(name)) {
            Ok(v) => v,
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
                Config::create_default(dir_path, name)?
            }
            Err(e) => return Err(Error::IO(e)),
        };

        // Read file
        let mut conf_file_str = String::with_capacity(2048);
        conf_file.read_to_string(&mut conf_file_str)?;

        // Parse toml string
        match toml::from_str(&mut conf_file_str) {
            Ok(v) => Ok(v),
            Err(_) => Err(Error::Unknown),
        }
    }

    /// Try to create default config file.
    fn create_default(dir_path: PathBuf, name: &str) -> Result<File, Error> {
        // Create dir if not exists yet
        if !Path::new(&dir_path).exists() {
            fs::create_dir_all(&dir_path)?;
        }

        // Write file
        let mut conf_file = OpenOptions::new()
            .create(true)
            .write(true)
            .mode(0o600)
            .open(dir_path.join(name))?;
        conf_file.write_all(DEFAULT.as_bytes())?;

        Ok(conf_file)
    }
}

const DEFAULT: &'static str = "\
# Path to database.
# db_path = \"/path/to/database\"

# Outer encryption key. (store it somewhere else)
# db_key = \"outer encryption key\"

# Path to ipc socket.
# ipc_socket_path = \"/tmp/pasd.sock\"
";
