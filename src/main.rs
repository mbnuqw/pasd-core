#![forbid(unsafe_code)]
extern crate chrono;
extern crate con;
extern crate rand;
extern crate rmp_serde as msgpack;
extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
extern crate aes;
extern crate block_cipher_trait;
extern crate block_modes;
extern crate hmac;
extern crate scrypt;
extern crate sha2;
extern crate toml;

pub mod config;
pub mod db;
pub mod errors;
pub mod handlers;
pub mod key;
pub mod secret;
pub mod utils;

use config::Config;
use db::DB;
use errors::Error;
use handlers::add_key::add_key_handler;
use handlers::add_secret::add_secret_handler;
use handlers::get_secret::get_secret_handler;
use handlers::list_keys::list_key_handler;
use handlers::list_secrets::list_secrets_handler;
use handlers::remove_key::remove_key_handler;
use handlers::remove_secret::remove_secret_handler;
use std::sync::{Arc, Mutex};

fn main() -> Result<(), Error> {
    // Initialize config and database
    let config = Config::load();
    let db = DB::new(&config);

    // ---
    let shared_db = Arc::new(Mutex::new(db));

    // Setup server
    let mut server = con::Server::new(shared_db);

    server.on(
        con::ClientName::Any,
        con::MsgName::Is("add-key"),
        add_key_handler,
    )?;

    server.on(
        con::ClientName::Any,
        con::MsgName::Is("add-secret"),
        add_secret_handler,
    )?;

    server.on(
        con::ClientName::Any,
        con::MsgName::Is("remove-key"),
        remove_key_handler,
    )?;

    server.on(
        con::ClientName::Any,
        con::MsgName::Is("remove-secret"),
        remove_secret_handler,
    )?;

    server.on(
        con::ClientName::Any,
        con::MsgName::Is("list-keys"),
        list_key_handler,
    )?;

    server.on(
        con::ClientName::Any,
        con::MsgName::Is("list-secrets"),
        list_secrets_handler,
    )?;

    server.on(
        con::ClientName::Any,
        con::MsgName::Is("get-secret"),
        get_secret_handler,
    )?;

    // Listen clients (blocked)
    match server.listen("/tmp/pasd.sock") {
        Ok(_) => (),
        Err(err) => println!("Cannot listen: {:?}", err),
    };

    Ok(())
}
