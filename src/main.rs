use std::sync::Arc;
use std::sync::mpsc::sync_channel;
use std::thread;
use std::{path::Path, io::stdin};
use clap::{Parser, Subcommand};
use serde::{Serialize, Deserialize};
use serde_json::Value;

mod frida;
mod storage;

#[derive(Subcommand)]
enum Commands {
    Init,
    Add {
        device_id: String,
        nick: String,
    },
    Send {
        #[arg(short, long)]
        to: String,
    }
}

#[derive(Parser)]
struct Cli {
    #[arg(short, long, value_name = "LMDB_DB", default_value_t = storage::STORAGE_FILE.to_string())]
    frida_storage: String,
    #[arg(short, long, value_name = "LMDB_DB", default_value_t = String::from("app.db"))]
    app_storage: String,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Deserialize, Serialize)]
struct Group {
    admins: Vec<String>,
    parents: Vec<String>,
    children: Option<Vec<String>>,
    writers: Vec<String>,
    #[serde(rename = "contactLevel")]
    contact_level: bool,
    name: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum GroupOrId {
    Group {
        id: String,
        value: Group,
    },
    Id(String),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "msgType")]
enum KahloMessage {
    /// TODO: Probably doesn't belong at this level of the protocol
    #[serde(rename = "requestUpdateLinked")]
    RequestUpdateLinked {
        #[serde(rename = "newLinkedMembers")]
        new_linked_members: Vec<GroupOrId>,
        #[serde(rename = "tempName")]
        temp_name: String,
        #[serde(rename = "srcIdkey")]
        src_id_key: String,
    },
    #[serde(rename = "updateData")]
    UpdateData {
        key: String,
        value: Value,
    },
    #[serde(rename = "deleteData")]
    DeleteData {
        key: String,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {

    let cli = Cli::parse();

    let frida = Arc::new(frida::Frida::new(storage::DB::new(Path::new(&cli.frida_storage))?)?);

    let app_db = storage::DB::new(Path::new(&cli.app_storage))?;

    let (sender, receiver) = sync_channel(10);
    frida.connect_socketio(sender)?;

    {
        let frida = frida.clone();
        thread::spawn(move || {
            for (s, msg) in receiver.iter() {
                if s == frida.device_id {
                    println!("> self {}", String::from_utf8_lossy(msg.as_slice()));
                } else {
                    if let Ok(kahlo_msg) = serde_json::from_slice::<KahloMessage>(msg.as_slice()) {
                        println!("> {} {:?}", s, kahlo_msg);
                    } else {
                        println!("> {} {}", s, String::from_utf8_lossy(msg.as_slice()));
                    }
                }
            }
        });
    }

    match cli.command {
        Commands::Init => {
            println!("{}", frida.device_id);
        },
        Commands::Add {device_id, nick} => {
            app_db.set_item(format!("friends/{}", nick), device_id)?;
        },
        Commands::Send {to: nick} => {
            let idkey_str: String = app_db.get_item(format!("friends/{}", nick))?;
            loop {
                let mut msg = String::new();
                stdin().read_line(&mut msg)?;
                frida.send_to(vec![frida.device_id.clone(), idkey_str.clone()], msg.trim().to_string())?;
            }
        },
    }
    Ok(())
}
