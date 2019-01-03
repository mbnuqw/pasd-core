use std::sync::{Arc, Mutex};

use con::server::SharedState;
use con::Msg;
use db::DB;
use errors::Error;
use key::Passwords;

#[derive(Debug, Deserialize)]
struct RemoveSecretArgs {
    name: String,
    passwords: Passwords,
}

#[derive(Serialize)]
struct RemoveSecretAns {
    error: Option<String>,
}

impl RemoveSecretAns {
    pub fn json(err: Option<Error>) -> Option<Vec<u8>> {
        let mut ans = RemoveSecretAns { error: None };

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
            Err(e) => return RemoveSecretAns::json(Some(Error::JSON(e))),
        };

        Some(json)
    }
}

pub fn remove_secret_handler<T>(
    msg: Msg,
    _: SharedState<T>,
    shared_db: Arc<Mutex<DB>>,
) -> Option<Vec<u8>> {
    let args_json = match msg.body {
        Some(body) => body,
        None => return RemoveSecretAns::json(Some(Error::IncorrectReq)),
    };

    // Parse json
    let args: RemoveSecretArgs = match serde_json::from_slice(&args_json) {
        Ok(k) => k,
        Err(e) => return RemoveSecretAns::json(Some(Error::JSON(e))),
    };
    let passwords = args.passwords.clone();

    // Remove key
    let mut db = match shared_db.lock() {
        Ok(db) => db,
        Err(_) => return RemoveSecretAns::json(Some(Error::Internal)),
    };
    match db.rm_secret(&args.name, passwords) {
        Ok(_) => (),
        Err(err) => return RemoveSecretAns::json(Some(err)),
    }

    RemoveSecretAns::json(None)
}
