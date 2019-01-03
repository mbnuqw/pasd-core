use con::server::SharedState;
use con::Msg;
use db::DB;
use errors::Error;
use key::{Key, AddKeyArgs};
use std::sync::{Arc, Mutex};

#[derive(Serialize)]
pub struct AddKeyAns {
    error: Option<String>,
}

impl AddKeyAns {
    pub fn json(err: Option<Error>) -> Option<Vec<u8>> {
        let mut ans = AddKeyAns { error: None };

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
            Err(e) => return AddKeyAns::json(Some(Error::JSON(e))),
        };

        Some(json)
    }
}

pub fn add_key_handler<T>(msg: Msg, _: SharedState<T>, shared_db: Arc<Mutex<DB>>) -> Option<Vec<u8>> {
    let args_json = match msg.body {
        Some(body) => body,
        None => return AddKeyAns::json(Some(Error::IncorrectReq)),
    };

    // Parse json
    let key_args: AddKeyArgs = match serde_json::from_slice(&args_json) {
        Ok(k) => k,
        Err(e) => return AddKeyAns::json(Some(Error::JSON(e))),
    };
    let text_keys = key_args.passwords.clone();

    // Unlock database
    let mut db = match shared_db.lock() {
        Ok(db) => db,
        Err(_) => return AddKeyAns::json(Some(Error::Internal)),
    };

    // Create key
    let key = match Key::from_args(key_args) {
        Ok(k) => k,
        Err(err) => return AddKeyAns::json(Some(err)),
    };

    // Add new key
    match db.add_key(key, text_keys) {
        Ok(_) => AddKeyAns::json(None),
        Err(err) => AddKeyAns::json(Some(err)),
    }
}
