use con::server::SharedState;
use con::Msg;
use db::DB;
use errors::Error;
use secret::{SecretInfo};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Serialize)]
struct ListSecretsAns {
    secrets: Vec<SecretInfo>,
    error: Option<String>,
}

impl ListSecretsAns {
    pub fn json(secrets: Option<Vec<SecretInfo>>, err: Option<Error>) -> Option<Vec<u8>> {
        let mut ans = ListSecretsAns {
            secrets: vec![],
            error: None,
        };

        // Check error
        match err {
            Some(ref err) => {
                ans.error = Some(err.json());
            }
            None => (),
        };

        // Put secrets
        if let Some(secrets) = secrets {
            ans.secrets = secrets;
        }

        // Serialize
        let json = match serde_json::to_vec(&ans) {
            Ok(v) => v,
            Err(e) => return ListSecretsAns::json(None, Some(Error::JSON(e))),
        };

        Some(json)
    }
}

pub fn list_secrets_handler<T>(
    _: Msg,
    _: SharedState<T>,
    shared_db: Arc<Mutex<DB>>,
) -> Option<Vec<u8>> {
    // Lock database
    let mut db = match shared_db.lock() {
        Ok(db) => db,
        Err(_) => return ListSecretsAns::json(None, Some(Error::Internal)),
    };

    match db.list_secrets() {
        Ok(secrets) => return ListSecretsAns::json(Some(secrets), None),
        Err(err) => return ListSecretsAns::json(None, Some(err)),
    }
}