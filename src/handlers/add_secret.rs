use con::server::SharedState;
use con::Msg;
use db::DB;
use errors::Error;
use secret::AddSecretArgs;
use std::sync::{Arc, Mutex};

#[derive(Serialize)]
pub struct AddSecretAns {
    error: Option<String>,
}

impl AddSecretAns {
    pub fn json(err: Option<Error>) -> Option<Vec<u8>> {
        let mut ans = AddSecretAns { error: None };

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
            Err(e) => return AddSecretAns::json(Some(Error::JSON(e))),
        };

        Some(json)
    }
}

pub fn add_secret_handler<T>(
    msg: Msg,
    _: SharedState<T>,
    shared_db: Arc<Mutex<DB>>,
) -> Option<Vec<u8>> {
    let args_json = match msg.body {
        Some(body) => body,
        None => return AddSecretAns::json(Some(Error::IncorrectReq)),
    };

    // Parse json
    let args: AddSecretArgs = match serde_json::from_slice(&args_json) {
        Ok(k) => k,
        Err(e) => return AddSecretAns::json(Some(Error::JSON(e))),
    };
    println!(" → Add secret args: {:?}", args);
    let passwords = args.passwords.clone();

    let mut db = match shared_db.lock() {
        Ok(db) => db,
        Err(_) => return AddSecretAns::json(Some(Error::Internal)),
    };

    match db.add_secret(args, passwords) {
        Ok(_) => AddSecretAns::json(None),
        Err(err) => AddSecretAns::json(Some(err)),
    }
}
