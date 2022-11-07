use std::{sync::{Arc, Mutex, mpsc::SyncSender}, collections::HashMap};

use reqwest::blocking::Client;
use serde::Deserialize;
use rust_socketio::ClientBuilder;
use vodozemac::{olm::{Account, Session, OlmMessage, SessionConfig}, Curve25519PublicKey};

pub mod storage;


pub struct Frida<D> {
    account: Arc<Mutex<Account>>,
    pub device_id: String,
    database: Arc<D>,
    rest_client: Client,
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
pub struct Message {
    encPayload: serde_json::Value,
    sender: String,
    seqID: usize,
}

impl<D: storage::DB + Send + Sync + 'static> Frida<D> {
    pub fn new(database: D) -> Result<Frida<D>, Box<dyn std::error::Error>> {
        let account = database.get_item("account")
            .map(Account::from_pickle)
            .unwrap_or_else(|_| {
                let account = Account::new();
                database.set_item("account", account.pickle()).expect("set");
                account
            });
        let device_id = account.curve25519_key().to_base64();
        Ok(Frida {
            account: Arc::new(Mutex::new(account)),
            device_id,
            database: Arc::new(database),
            rest_client: Client::builder().build()?,
        })
    }

    pub fn send_to<M: AsRef<[u8]>>(&self, idkeys: Vec<String>, msg: M) -> Result<(), Box<dyn std::error::Error>> {
        let mut batch = Vec::new();
        for idkey_str in idkeys.iter() {
            if *idkey_str == self.device_id {
                let local_seq: u64 = self.database.get_item("_local_seq").unwrap_or(1);
                self.database.set_item("_local_seq", local_seq + 1)?;
                self.database.set_item(format!("_self_items/{}", local_seq), msg.as_ref())?;
                batch.push(serde_json::json!({
                    "deviceId": idkey_str,
                    "payload": local_seq,
                }));
                continue;
            }
            let session_key = ["session/", idkey_str.as_str()].join("/");
            let mut session = if let Ok(session) = self.database.get_item(&session_key) {
                Session::from_pickle(session)
            } else {
                #[derive(Deserialize, Debug)]
                struct Otkey {
                    otkey: String
                }
                let res : Otkey = self.rest_client.get("http://localhost:8080/devices/otkey").query(&[("device_id", &idkey_str)])
                    .send()?.json()?;
                let one_time_key = Curve25519PublicKey::from_base64(res.otkey.as_str())?;
                let idkey = Curve25519PublicKey::from_base64(idkey_str.as_str())?;
                let session = self.account.lock().unwrap().create_outbound_session(SessionConfig::version_2(), idkey, one_time_key);
                self.database.set_item(&session_key, session.pickle())?;
                session
            };
            let payload = session.encrypt(&msg);
            batch.push(serde_json::json!({
                "deviceId": idkey_str,
                "payload": payload,
            }));
            self.database.set_item(&session_key, session.pickle())?
        }
        self.rest_client.post("http://localhost:8080/message")
            .bearer_auth(&self.device_id)
            .json(&serde_json::json!({
                "batch": batch,
            })).send()?;
        Ok(())
    }

    pub fn connect_socketio(&self, sender: SyncSender<(String, Vec<u8>)>) -> Result<(), Box<dyn std::error::Error>> {
        let db = self.database.clone();
        let account = self.account.clone();
        let device_id = self.device_id.clone();
        let sender = sender;
        let rest_client = self.rest_client.clone();
        ClientBuilder::new("http://localhost:8080")
            .auth(serde_json::json!({
                "deviceId": &device_id,
            }))
            .on_any(move |event, payload, _client| {
                let event: String = event.into();
                match event.as_str() {
                    "addOtkeys" => {
                        let mut account = account.lock().unwrap();
                        account.generate_one_time_keys(10);
                        let otkeys = account.one_time_keys();
                        rest_client.post("http://localhost:8080/self/otkeys")
                            .json(&otkeys.iter().map(|(key, value)| (key.to_base64(), value.to_base64())).collect::<HashMap<String, String>>())
                            .bearer_auth(&device_id)
                            .send().expect("publish otkeys");
                        account.mark_keys_as_published();
                        db.set_item("account", account.pickle()).expect("set_item");
                    },
                    "noiseMessage" => {
                        if let rust_socketio::Payload::String(msgs) = payload {
                            let mut messages: Vec<Message> = serde_json::from_str(msgs.as_str()).expect("payload");
                            let mut max_seq_id = None;
                            for msg in messages.drain(..) {
                                max_seq_id = Some(std::cmp::max(msg.seqID, max_seq_id.unwrap_or(msg.seqID)));
                                if msg.sender == device_id {
                                    let local_seq: Result<u64, _> = serde_json::from_value(msg.encPayload);
                                    if let Ok(local_seq) = local_seq {
                                        let plaintext: Vec<u8> = db.get_item(format!("_self_items/{}", local_seq)).expect("get_item");
                                        db.delete_item(format!("_self_items/{}", local_seq)).expect("get_item");
                                        sender.send((msg.sender, plaintext)).expect("send");
                                    }
                                } else {
                                    let session_key = ["session/", msg.sender.as_str()].join("/");
                                    let enc_payload = serde_json::from_value(msg.encPayload);
                                    match enc_payload {
                                        Ok(enc_payload @ OlmMessage::Normal(_)) => {
                                            if let Ok(mut session) = db.get_item(&session_key).map(Session::from_pickle) {
                                                let plaintext = session.decrypt(&enc_payload).expect("decrypt");
                                                sender.send((msg.sender, plaintext)).expect("send");
                                                db.set_item(&session_key, session.pickle()).expect("set_item");
                                            }
                                        },
                                        Ok(OlmMessage::PreKey(pre_key_message)) => {
                                            let idkey = Curve25519PublicKey::from_base64(msg.sender.as_str()).expect("key");
                                            let mut account = account.lock().expect("lock");
                                            let session_result = account.create_inbound_session(idkey, &pre_key_message).expect("inbound");

                                            db.set_item(&session_key, session_result.session.pickle()).expect("set_item");
                                            sender.send((msg.sender, session_result.plaintext)).expect("send");
                                        },
                                        Err(_) => {}
                                    }
                                }
                            }

                            if let Some(max_seqid) = max_seq_id {
                                rest_client.delete("http://localhost:8080/self/messages")
                                    .bearer_auth(device_id.clone())
                                    .query(&[("seqID", max_seqid)])
                                    .send().expect("send");
                            }
                        }
                    }
                    _ => {}
                }
            }).connect()?;
        Ok(())
    }
}
