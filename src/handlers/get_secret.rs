use std::sync::{Arc, Mutex};

use con::server::SharedState;
use con::Msg;
use db::DB;
use errors::Error;
use key::Passwords;
use secret::SecretType;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GetSecretArgs {
    pub query: Vec<String>,
    pub passwords: Passwords,
}

#[derive(Debug, Clone, Serialize)]
struct GetSecretAns {
    secret: Option<Vec<u8>>,
    #[serde(rename = "type")]
    secret_type: Option<SecretType>,
    error: Option<String>,
}

impl GetSecretAns {
    pub fn json(
        secret: Option<Vec<u8>>,
        secret_type: Option<SecretType>,
        err: Option<Error>,
    ) -> Option<Vec<u8>> {
        let mut ans = GetSecretAns {
            secret: secret,
            secret_type: secret_type,
            error: None,
        };

        // Check error
        match err {
            Some(ref err) => {
                ans.error = Some(err.json());
            }
            None => (),
        };

        // Serialize
        let json = match serde_json::to_vec(&ans) {
            Ok(v) => v,
            Err(e) => return GetSecretAns::json(None, None, Some(Error::JSON(e))),
        };

        Some(json)
    }
}

pub fn get_secret_handler<T>(
    msg: Msg,
    _: SharedState<T>,
    shared_db: Arc<Mutex<DB>>,
) -> Option<Vec<u8>> {
    let args_json = match msg.body {
        Some(body) => body,
        None => return GetSecretAns::json(None, None, Some(Error::IncorrectReq)),
    };

    // Parse json
    let args: GetSecretArgs = match serde_json::from_slice(&args_json) {
        Ok(k) => k,
        Err(e) => return GetSecretAns::json(None, None, Some(Error::JSON(e))),
    };
    let passwords = args.passwords.clone();

    // Lock database
    let mut db = match shared_db.lock() {
        Ok(db) => db,
        Err(_) => return GetSecretAns::json(None, None, Some(Error::Internal)),
    };

    match db.get_secret(args.query, passwords) {
        Ok((v, t)) => return GetSecretAns::json(Some(v), Some(t), None),
        Err(err) => return GetSecretAns::json(None, None, Some(err)),
    }
}
