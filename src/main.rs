use std::sync::mpsc::sync_channel;
use std::thread;
use std::{path::Path, io::stdin};
use clap::{Parser, Subcommand};

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

fn main() -> Result<(), Box<dyn std::error::Error>> {

    let cli = Cli::parse();

    let frida = frida::Frida::new(storage::DB::new(Path::new(&cli.frida_storage))?)?;

    let app_db = storage::DB::new(Path::new(&cli.app_storage))?;

    let (sender, receiver) = sync_channel(10);
    frida.connect_socketio(sender)?;
    let device_id = frida.device_id.clone();
    thread::spawn(move || {
        for (s, msg) in receiver.iter() {
            if s == device_id {
                println!("> self {}", String::from_utf8_lossy(msg.as_slice()));
            } else {
                println!("> {} {}", s, String::from_utf8_lossy(msg.as_slice()));
            }
        }
    });

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
