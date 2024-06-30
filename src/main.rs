use std::process;
use tokio::io::{self, split, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::select;

#[derive(Debug)]
enum Opcode {
    Help,
    Connect,
    Send,
    Leave,
    Quit,
    Listen,
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
        _ => Opcode::Unknown,
    };
    let args = input[1..].iter().map(|s| s.to_string()).collect();
    Command { op, args }
}

fn help() {
    println!("Commands:");
    println!("  help                  - Show this help message");
    println!("  connect <host> <port> - Connect to a peer");
    println!("  send <message>        - Send a message to the connected peer");
    println!("  leave                 - Leave the current connection");
    println!("  quit                  - Quit the application");
    println!("  listen <host> <port>  - Listen for incoming connections");
}

async fn peer_loop(stream: &mut TcpStream) -> Result<(), io::Error> {
    println!("Connection established with peer {}", stream.peer_addr()?);
    let (mut reader, mut writer) = split(stream);
    let mut stdin = BufReader::new(io::stdin()).lines();

    loop {
        let mut msg = [0u8; 100];

        select! {
            line = stdin.next_line() => {
                if let Some(line) = line? {
                    let cmd = parse_cmd(line.split_whitespace().collect());
                    match cmd.op {
                        Opcode::Help => help(),
                        Opcode::Connect => println!("Please leave your current connection before connecting to another peer."),
                        Opcode::Send => handle_send(cmd, &mut writer).await?,
                        Opcode::Leave => break,
                        Opcode::Quit => process::exit(0),
                        Opcode::Listen => println!("Please leave your current connection before listening for a new peer."),
                        Opcode::Unknown => println!("Unknown opcode. Please use help."),
                    }
                }
            }
            n = reader.read(&mut msg) => {
                if n? == 0 {
                    break;
                }
                println!("GOT {}", String::from_utf8_lossy(&msg));
            }
        }
    }

    Ok(())
}

async fn handle_connect(cmd: Command) -> Result<(), io::Error> {
    let host = &cmd.args[0];
    let port = cmd.args[1].parse::<u16>().expect("Invalid Port");

    let mut stream = TcpStream::connect(format!("{}:{}", host, port)).await?;

    peer_loop(&mut stream).await?;

    Ok(())
}

async fn handle_send(
    cmd: Command,
    writer: &mut tokio::io::WriteHalf<&mut TcpStream>,
) -> Result<(), io::Error> {
    let mut final_str = String::new();

    for word in cmd.args {
        final_str.push_str(&word);
        final_str.push(' ');
    }

    writer.write_all(final_str.as_bytes()).await?;

    Ok(())
}

async fn handle_listen(cmd: Command) -> Result<(), io::Error> {
    let host = &cmd.args[0];
    let port = cmd.args[1].parse::<u16>().expect("Not a valid port");
    println!("Listening for peers on port {}", port);
    let listener = TcpListener::bind(format!("{}:{}", host, port)).await?;

    let (mut stream, _) = listener.accept().await?;

    peer_loop(&mut stream).await?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    let stdin = io::stdin();
    let mut lines = BufReader::new(stdin).lines();

    loop {
        if let Some(line) = lines.next_line().await? {
            let cmd = parse_cmd(line.split_whitespace().collect());
            match cmd.op {
                Opcode::Help => help(),
                Opcode::Connect => handle_connect(cmd).await?,
                Opcode::Send => println!("Not connected to any peer."),
                Opcode::Leave => println!("Not connected to any peer."),
                Opcode::Quit => break,
                Opcode::Listen => handle_listen(cmd).await?,
                Opcode::Unknown => println!("Unknown opcode. Please use help."),
            }
        }
    }

    Ok(())
}
