use md5;
use num_bigint::BigUint;
use securechat::message::{receive_message, send_message, Message, MessageOpcode};
use securechat::rsa::{Keypair, N_SIZE, SIGNATURE_SIZE};
use std::env;
use tokio::io::{self, AsyncWriteExt};
use tokio::net::TcpListener;

async fn ttp_server(ip: String, port: u16) -> Result<(), io::Error> {
    let listener = TcpListener::bind(format!("{}:{}", ip, port)).await?;

    let ttp_keypair = Keypair::new(None, None);

    println!("TTP Listening on {}:{}", ip, port);

    loop {
        let (mut socket, _) = listener.accept().await?;
        let keypair_clone = ttp_keypair.clone();

        tokio::spawn(async move {
            let msg = receive_message(&mut socket)
                .await
                .expect("Failed to receive message");
            println!("Receive message: {:?}", msg.op);
            let payload = msg.payload;
            match msg.op {
                MessageOpcode::RequestCertificate => {
                    let name_length = u32::from_be_bytes(payload[0..4].try_into().unwrap());
                    let to_sign = &payload[4..4 + name_length as usize + 256];
                    let digest = md5::compute(to_sign);
                    let signature = keypair_clone.sign(&BigUint::from_bytes_be(&digest.to_vec()));
                    let mut resp = Message {
                        op: MessageOpcode::CertSigned,
                        payload: signature.to_bytes_be(),
                    };
                    send_message(&mut socket, &mut resp)
                        .await
                        .expect("Failed to send response to client");
                    socket.shutdown().await.expect("Failed to shutdown socket");
                }
                MessageOpcode::ValidateCertificate => {
                    let name_length = u32::from_be_bytes(payload[0..4].try_into().unwrap());
                    let signed_part = &payload[4..4 + name_length as usize + N_SIZE];
                    let signature = &payload[4 + name_length as usize + N_SIZE
                        ..4 + name_length as usize + N_SIZE + SIGNATURE_SIZE];
                    let digest = md5::compute(signed_part);
                    let is_signature_valid = keypair_clone.validate(
                        &BigUint::from_bytes_be(&digest.to_vec()),
                        &BigUint::from_bytes_be(signature),
                    );
                    let mut payload = vec![0; 1];
                    if is_signature_valid {
                        payload[0] = 1;
                    }
                    let mut resp = Message {
                        op: MessageOpcode::CertSigned,
                        payload,
                    };
                    send_message(&mut socket, &mut resp)
                        .await
                        .expect("Failed to send response to client");
                    socket.shutdown().await.expect("Failed to shutdown socket");
                }
                _ => println!("Unimplemented"),
            }
        });
    }
}

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        return Err(io::Error::other(format!(
            "Usage: ./{} <IP Address> <Port>",
            args[0]
        )));
    }
    let ip = &args[1];
    let port = args[2].parse::<u16>().expect("Not a valid port");

    ttp_server(ip.to_string(), port).await?;

    Ok(())
}
