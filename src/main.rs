use std::{path::Path, io::stdin};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use lmdb::{Transaction, WriteFlags};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use vodozemac::{olm::{Account, SessionConfig, Session, OlmMessage}, Curve25519PublicKey};
use rust_socketio::{ClientBuilder};

const STORAGE_FILE: &'static str = "storage.db";

pub struct DB {
    dbenv: lmdb::Environment,
    db: lmdb::Database,
}

impl DB {
    pub fn new(path: &Path) -> Result<DB, lmdb::Error> {
        let dbenv = lmdb::Environment::new()
            .set_flags(lmdb::EnvironmentFlags::NO_SUB_DIR)
            .open(path)?;
        let db = dbenv.open_db(None)?;
        Ok(DB {
            dbenv, db
        })
    }

    pub fn get_item<K: AsRef<[u8]>, R: DeserializeOwned>(&self, key: K) -> Result<R, Box<dyn std::error::Error>> {
        let txn = self.dbenv.begin_ro_txn()?;
        let result = txn.get(self.db, &key)?;
        let result = serde_json::from_slice(result)?;
        txn.commit()?;
        Ok(result)
    }

    pub fn set_item<K: AsRef<[u8]>, V: Serialize>(&self, key: K, value: V) -> Result<(), Box<dyn std::error::Error>> {
        let mut txn = self.dbenv.begin_rw_txn()?;
        txn.put(
            self.db,
            &key,
            &serde_json::to_vec(&value)?,
            WriteFlags::empty(),
        )?;
        txn.commit()?;
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {

    let mut args = std::env::args();
    args.next();

    let storage_file = args.next().unwrap_or(STORAGE_FILE.to_string());
    let db = Arc::new(DB::new(Path::new(&storage_file))?);

    let account = Arc::new(Mutex::new(db.get_item("account")
        .map(Account::from_pickle)
        .unwrap_or_else(|_| {
            Account::new()
        })));

    let device_id = {
        let account = account.lock().unwrap();
        account.curve25519_key().to_base64()
    };

    let rest_client = {
        use reqwest::{blocking::Client};
        Client::builder().build()?
    };

    let did = device_id.clone();
    let db2 = db.clone();
    let account2 = account.clone();
    ClientBuilder::new("http://localhost:8080")
        .auth(serde_json::json!({
            "deviceId": &device_id,
        }))
        .on("noiseMessage", move |payload, _client| {

            #[derive(Deserialize, Debug)]
            #[allow(non_snake_case)]
            struct Message {
                encPayload: OlmMessage,
                sender: String,
                seqID: usize,
            }

            if let rust_socketio::Payload::String(msgs) = payload {
                let messages: Vec<Message> = serde_json::from_str(msgs.as_str()).expect("payload");
                for msg in messages.iter() {
                    let session_key = ["session/", msg.sender.as_str()].join("/");
                    match &msg.encPayload {
                        OlmMessage::Normal(_) => {
                            if let Ok(mut session) = db2.get_item(&session_key).map(Session::from_pickle) {
                                let plaintext = session.decrypt(&msg.encPayload).expect("decrypt");
                                db2.set_item(&session_key, session.pickle()).expect("set_item");
                                println!("> {}: {}", msg.sender, String::from_utf8_lossy(plaintext.as_ref()));
                            }
                        },
                        OlmMessage::PreKey(pre_key_message) => {
                            let idkey = Curve25519PublicKey::from_base64(msg.sender.as_str()).expect("key");
                            let mut account = account2.lock().expect("lock");
                            let session_result = account.create_inbound_session(idkey, &pre_key_message).expect("inbound");

                            db2.set_item(&session_key, session_result.session.pickle()).expect("set_item");
                            println!("> {}: {}", msg.sender, String::from_utf8_lossy(session_result.plaintext.as_ref()))
                        }
                    }
                }

                if let Some(max_seqid) = messages.iter().max_by_key(|message| message.seqID).map(|m| m.seqID) {
                    let rest_client = {
                        use reqwest::{blocking::Client};
                        Client::builder().build().expect("builder")
                    };

                    rest_client.delete("http://localhost:8080/self/messages")
                        .bearer_auth(did.clone())
                        .query(&[("seqID", max_seqid)])
                        .send().expect("send");
                }
            }

        })
        .connect()?;


    let cmd = args.next().unwrap_or("init".to_string());
    match cmd.as_str() {
        "init" => {
            let mut account = account.lock().unwrap();
            account.generate_one_time_keys(10);
            let otkeys = account.one_time_keys();
            println!("{}", &device_id);
            rest_client.post("http://localhost:8080/self/otkeys")
                .json(&otkeys.iter().map(|(key, value)| (key.to_base64(), value.to_base64())).collect::<HashMap<String, String>>())
                .bearer_auth(&device_id)
                .send()?;
            account.mark_keys_as_published();
            db.set_item("account", account.pickle())?;
        },
        "send" => {
            let account = account.lock().unwrap();
            if let Some(idkey_str) = args.next() {
                loop {
                    let mut msg = String::new();
                    stdin().read_line(&mut msg)?;

                    let session_key = ["session/", idkey_str.as_str()].join("/");
                    let mut session = if let Ok(session) = db.get_item(&session_key) {
                        Session::from_pickle(session)
                    } else {
                        eprintln!("Need a otkey");
                        #[derive(Deserialize, Debug)]
                        struct Otkey {
                            otkey: String
                        }
                        let res : Otkey = rest_client.get("http://localhost:8080/devices/otkey").query(&[("device_id", &idkey_str)])
                            .send()?.json()?;
                        let one_time_key = Curve25519PublicKey::from_base64(res.otkey.as_str())?;
                        let idkey = Curve25519PublicKey::from_base64(idkey_str.as_str())?;
                        let session = account.create_outbound_session(SessionConfig::version_2(), idkey, one_time_key);
                        db.set_item(&session_key, session.pickle())?;
                        session
                    };
                    let payload = session.encrypt(msg.trim());
                    rest_client.post("http://localhost:8080/message")
                        .bearer_auth(&device_id)
                        .json(&serde_json::json!({
                            "batch": [{
                                "deviceId": idkey_str,
                                "payload": payload,
                            }]
                        })).send()?;
                    db.set_item(&session_key, session.pickle())?;
                }
            } else {
                eprint!("3 arguments expected");
            }
        },
        _ => {}
    }
    std::thread::sleep(std::time::Duration::from_secs(1));
    Ok(())
}
