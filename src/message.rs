use aes::Aes128;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::rsa::{Keypair, PublicKey};

const MAX_MESSAGE_SIZE: usize = 2048;

pub struct Message {
    pub op: MessageOpcode,
    pub payload: Vec<u8>,
}

impl MessageOpcode {
    fn index(&self) -> u8 {
        *self as u8
    }

    fn opcode_to_element(idx: u8) -> MessageOpcode {
        match idx {
            0 => Self::HandshakeStart,
            1 => Self::CertificateShow,
            2 => Self::RequestCertificate,
            3 => Self::CertSigned,
            4 => Self::ValidateCertificate,
            5 => Self::ValidationResponse,
            6 => Self::CertificateAccepted,
            7 => Self::CertificateRejected,
            _ => Self::Other,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum MessageOpcode {
    HandshakeStart,
    CertificateShow,
    RequestCertificate,
    CertSigned,
    ValidateCertificate,
    ValidationResponse,
    CertificateAccepted,
    CertificateRejected,
    Other,
}

pub async fn send_message(socket: &mut TcpStream, msg: &mut Message) -> Result<usize, io::Error> {
    let mut data = vec![msg.op.index()];
    data.append(&mut msg.payload);

    socket.write(&data).await
}

pub async fn receive_message(socket: &mut TcpStream) -> Result<Message, io::Error> {
    let mut buf = [0u8; MAX_MESSAGE_SIZE];
    let n = socket.read(&mut buf).await?;
    let op = buf[0];
    let payload = buf[1..n].to_vec();

    Ok(Message {
        op: MessageOpcode::opcode_to_element(op),
        payload,
    })
}

pub struct Peer {
    keypair: Keypair,
    pub cert: Option<Certificate>,
    pub stream: Option<TcpStream>,
    pub cipher: Option<Aes128>,
}

impl Peer {
    pub fn new() -> Self {
        Self {
            keypair: Keypair::new(None, None),
            cert: None,
            stream: None,
            cipher: None,
        }
    }

    // Ask the TTP for a certificate.
    pub async fn get_cert(
        &mut self,
        host: String,
        port: u16,
        name: String,
    ) -> Result<(), io::Error> {
        let name_len = name.len() as u32;

        let mut payload = vec![];
        payload.append(&mut name_len.to_be_bytes().to_vec());
        payload.append(&mut name.as_bytes().to_vec());
        payload.append(&mut self.keypair.public.n.to_bytes_be());

        let mut msg = Message {
            op: MessageOpcode::RequestCertificate,
            payload,
        };

        let mut stream = TcpStream::connect(format!("{}:{}", host, port)).await?;
        send_message(&mut stream, &mut msg).await?;
        let resp = receive_message(&mut stream).await?;
        if resp.op == MessageOpcode::CertSigned {
            self.cert = Some(Certificate {
                name,
                public: self.keypair.public.clone(),
                signature: resp.payload,
            })
        } else {
            return Err(io::Error::other("The TTP did not sign the certificate"));
        }

        stream.shutdown().await?;

        Ok(())
    }
}

#[derive(Debug)]
pub struct Certificate {
    name: String,
    public: PublicKey,
    signature: Vec<u8>,
}
