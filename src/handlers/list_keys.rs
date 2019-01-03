use con::server::SharedState;
use con::Msg;
use db::DB;
use errors::Error;
use key::KeyInfo;
use std::sync::{Arc, Mutex};

#[derive(Serialize)]
struct ListKeysAns {
    keys: Vec<KeyInfo>,
    error: Option<String>,
}

impl ListKeysAns {
    pub fn json(keys: Option<Vec<KeyInfo>>, err: Option<Error>) -> Option<Vec<u8>> {
        let mut ans = ListKeysAns {
            keys: vec![],
            error: None,
        };

        // Check error
        match err {
            Some(ref err) => {
                ans.error = Some(err.json());
            }
            None => (),
        };

        // Put keys
        if let Some(keys) = keys {
            ans.keys = keys;
        }

        // Serialize
        let json = match serde_json::to_vec(&ans) {
            Ok(v) => v,
            Err(e) => return ListKeysAns::json(None, Some(Error::JSON(e))),
        };

        Some(json)
    }
}

pub fn list_key_handler<T>(
    _: Msg,
    _: SharedState<T>,
    shared_db: Arc<Mutex<DB>>,
) -> Option<Vec<u8>> {
    let mut db = match shared_db.lock() {
        Ok(db) => db,
        Err(_) => return ListKeysAns::json(None, Some(Error::Internal)),
    };

    match db.list_keys() {
        Ok(keys) => return ListKeysAns::json(Some(keys), None),
        Err(err) => return ListKeysAns::json(None, Some(err)),
    }
}
