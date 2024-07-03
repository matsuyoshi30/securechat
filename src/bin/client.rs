use securechat::message::Peer;
use std::process;
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::select;

#[derive(Debug)]
enum Opcode {
    Help,
    Connect,
    Send,
    Leave,
    Quit,
    Listen,
    GetCert,
    Unknown,
}

#[derive(Debug)]
struct Command {
    op: Opcode,
    args: Vec<String>,
}

fn parse_cmd(input: Vec<&str>) -> Command {
    let op = match input[0] {
        "help" => Opcode::Help,
        "connect" => Opcode::Connect,
        "send" => Opcode::Send,
        "leave" => Opcode::Leave,
        "quit" => Opcode::Quit,
        "listen" => Opcode::Listen,
        "get_cert" => Opcode::GetCert,
        _ => Opcode::Unknown,
    };
    let args = input[1..].iter().map(|s| s.to_string()).collect();
    Command { op, args }
}

fn help() {
    println!("Commands:");
    println!("  help                                     - Show this help message");
    println!("  connect <host> <port>                    - Connect to a peer");
    println!("  send <message>                           - Send a message to the connected peer");
    println!("  leave                                    - Leave the current connection");
    println!("  quit                                     - Quit the application");
    println!("  listen <host> <port>                     - Listen for incoming connections");
    println!("  get_cert <TTP IP> <TTP PORT> <YOUR NAME> - Ask the TTP @ TTP_IP:TTP_PORT for a cert licensed to <YOUR NAME> and save it under <FILENAME>");
}

async fn peer_loop(peer: &mut Peer) -> Result<(), io::Error> {
    println!(
        "Connection established with peer {}",
        peer.stream.as_mut().unwrap().peer_addr().unwrap()
    );

    loop {
        let stdin = io::stdin();
        let br = BufReader::new(stdin);
        let mut lines = br.lines();

        select! {
            line = lines.next_line() => {
                if let Some(line) = line? {
                    let cmd = parse_cmd(line.split_whitespace().collect());
                    match cmd.op {
                        Opcode::Help => help(),
                        Opcode::Connect => println!("Please leave your current connection before connecting to another peer."),
                        Opcode::Send => handle_send(cmd, peer).await?,
                        Opcode::Leave => break,
                        Opcode::Quit => process::exit(0),
                        Opcode::Listen => println!("Please leave your current connection before listening for a new peer."),
                        Opcode::GetCert => println!("Please leave your current connection before listening for getting certificate."),
                        Opcode::Unknown => println!("Unknown opcode. Please use help."),
                    }
                }
            }
            text = peer.receive_text() => {
                let unwrap_text = text.unwrap();
                if unwrap_text.is_empty() {
                    break;
                }
                println!("GOT {}", unwrap_text);
            }
        }
    }

    peer.stream.as_mut().unwrap().shutdown().await?;
    println!("Connection closed successfully");

    Ok(())
}

async fn handle_connect(cmd: Command, peer: &mut Peer) -> Result<(), io::Error> {
    if cmd.args.len() < 4 {
        return Err(io::Error::other("Invalid number of arguments"));
    }

    let host = &cmd.args[0];
    let port = match cmd.args[1].parse::<u16>() {
        Ok(port) => port,
        Err(_) => return Err(io::Error::other("Invalid port number")),
    };
    let ttp_host = &cmd.args[2];
    let ttp_port = match cmd.args[3].parse::<u16>() {
        Ok(port) => port,
        Err(_) => return Err(io::Error::other("Invalid port number")),
    };

    peer.connect(host, port, ttp_host, ttp_port).await?;

    peer_loop(peer).await?;

    Ok(())
}

async fn handle_send(cmd: Command, peer: &mut Peer) -> Result<(), io::Error> {
    let mut final_str = String::new();

    for word in cmd.args {
        final_str.push_str(&word);
        final_str.push(' ');
    }

    peer.send_text(final_str).await?;

    Ok(())
}

async fn handle_listen(cmd: Command, peer: &mut Peer) -> Result<(), io::Error> {
    if cmd.args.len() < 4 {
        return Err(io::Error::other("Invalid number of arguments"));
    }

    let host = &cmd.args[0];
    let port = match cmd.args[1].parse::<u16>() {
        Ok(port) => port,
        Err(_) => return Err(io::Error::other("Invalid port number")),
    };
    let ttp_host = &cmd.args[2];
    let ttp_port = match cmd.args[3].parse::<u16>() {
        Ok(port) => port,
        Err(_) => return Err(io::Error::other("Invalid port number")),
    };
    println!("Listening for peers on port {}", port);

    peer.listen(host, port, ttp_host, ttp_port).await?;

    peer_loop(peer).await?;

    Ok(())
}

async fn handle_get_cert(cmd: Command, peer: &mut Peer) -> Result<(), io::Error> {
    if cmd.args.len() < 2 {
        return Err(io::Error::other("Invalid number of arguments"));
    }

    let host = &cmd.args[0];
    let port = match cmd.args[1].parse::<u16>() {
        Ok(port) => port,
        Err(_) => return Err(io::Error::other("Invalid port number")),
    };

    println!("Enter your name below");
    let stdin = io::stdin();
    let br = BufReader::new(stdin);
    io::stdout().flush().await?;
    let name = br.lines().next_line().await?.unwrap();

    peer.get_cert(host.to_string(), port, name).await?;
    println!("{:?}", peer.cert);

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    let mut peer = Peer::new();

    let stdin = io::stdin();
    let mut lines = BufReader::new(stdin).lines();

    loop {
        if let Some(line) = lines.next_line().await? {
            let cmd = parse_cmd(line.split_whitespace().collect());
            match cmd.op {
                Opcode::Help => help(),
                Opcode::Connect => handle_connect(cmd, &mut peer).await?,
                Opcode::Send => println!("Not connected to any peer."),
                Opcode::Leave => println!("Not connected to any peer."),
                Opcode::Quit => break,
                Opcode::Listen => handle_listen(cmd, &mut peer).await?,
                Opcode::GetCert => handle_get_cert(cmd, &mut peer).await?,
                Opcode::Unknown => println!("Unknown opcode. Please use help."),
            }
        }
    }

    Ok(())
}
