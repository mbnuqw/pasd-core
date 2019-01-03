use std::sync::{Arc, Mutex};

use con::server::SharedState;
use con::Msg;
use db::DB;
use errors::Error;
use key::Passwords;

#[derive(Debug, Deserialize)]
struct RemoveKeyArgs {
    name: String,
    passwords: Passwords,
}

#[derive(Serialize)]
struct RemoveKeyAns {
    error: Option<String>,
}

impl RemoveKeyAns {
    pub fn json(err: Option<Error>) -> Option<Vec<u8>> {
        let mut ans = RemoveKeyAns { error: None };

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
            Err(e) => return RemoveKeyAns::json(Some(Error::JSON(e))),
        };

        Some(json)
    }
}

pub fn remove_key_handler<T>(
    msg: Msg,
    _: SharedState<T>,
    shared_db: Arc<Mutex<DB>>,
) -> Option<Vec<u8>> {
    let args_json = match msg.body {
        Some(body) => body,
        None => return RemoveKeyAns::json(Some(Error::IncorrectReq)),
    };

    // Parse json
    let args: RemoveKeyArgs = match serde_json::from_slice(&args_json) {
        Ok(k) => k,
        Err(e) => return RemoveKeyAns::json(Some(Error::JSON(e))),
    };
    let passwords = args.passwords.clone();

    // Remove key
    let mut db = match shared_db.lock() {
        Ok(db) => db,
        Err(_) => return RemoveKeyAns::json(Some(Error::Internal)),
    };
    match db.rm_key(&args.name, passwords) {
        Ok(_) => (),
        Err(err) => return RemoveKeyAns::json(Some(err)),
    }

    RemoveKeyAns::json(None)
}
