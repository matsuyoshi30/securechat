use std::fmt::{self, Debug};
use std::net::SocketAddr;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::KeyInit;
use aes::Aes128;
use num_bigint::BigUint;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use tokio::io::{self, split, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};

use crate::aes::{decrypt, encrypt, AES_BLOCK_SIZE};
use crate::rsa::{Keypair, PublicKey, N_SIZE, RSA_EXP, SIGNATURE_SIZE};

const MAX_MESSAGE_SIZE: usize = 2048;

pub struct Message {
    pub op: MessageOpcode,
    pub payload: Vec<u8>,
}

impl Message {
    fn new(op: MessageOpcode, payload: Vec<u8>) -> Message {
        Message { op, payload }
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
    SymmetricKey,
    Text,
    Other,
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
            8 => Self::SymmetricKey,
            9 => Self::Text,
            _ => Self::Other,
        }
    }
}

pub async fn send_message(
    stream: &mut WriteHalf<TcpStream>,
    msg: &mut Message,
) -> Result<usize, io::Error> {
    let mut data = vec![msg.op.index()];
    data.append(&mut msg.payload);
    stream.write(&data).await
}

pub async fn receive_message(stream: &mut ReadHalf<TcpStream>) -> Result<Message, io::Error> {
    let mut buf = [0u8; MAX_MESSAGE_SIZE];
    let n = stream.read(&mut buf).await?;
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
    pub peer_addr: Option<SocketAddr>,
    pub stream: Option<(ReadHalf<TcpStream>, WriteHalf<TcpStream>)>,
    pub cipher: Option<Aes128>,
}

impl Peer {
    pub fn new() -> Self {
        Self {
            keypair: Keypair::new(None, None),
            cert: None,
            peer_addr: None,
            stream: None,
            cipher: None,
        }
    }

    pub async fn shutdown(&mut self) -> io::Result<()> {
        if let Some((_, ref mut writer)) = &mut self.stream {
            writer.shutdown().await?;
        }
        self.peer_addr = None;
        self.stream = None;
        self.cipher = None;
        Ok(())
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

        let stream = TcpStream::connect(format!("{}:{}", host, port)).await?;
        let (mut reader, mut writer) = split(stream);
        send_message(&mut writer, &mut msg).await?;
        let resp = receive_message(&mut reader).await?;
        if resp.op == MessageOpcode::CertSigned {
            self.cert = Some(Certificate {
                name,
                public: self.keypair.public.clone(),
                signature: resp.payload,
            })
        } else {
            return Err(io::Error::other("The TTP did not sign the certificate"));
        }

        let mut stream = reader.unsplit(writer);
        stream.shutdown().await?;

        Ok(())
    }

    // Connect to server, and perform the handshake
    pub async fn connect(
        &mut self,
        host: &String,
        port: u16,
        ttp_host: &String,
        ttp_port: u16,
    ) -> Result<(), io::Error> {
        let stream = TcpStream::connect(format!("{}:{}", host, port)).await?;
        let peer_addr = stream.peer_addr().unwrap();
        let (mut reader, mut writer) = split(stream);
        let ttp_stream = TcpStream::connect(format!("{}:{}", ttp_host, ttp_port)).await?;
        let (mut ttp_reader, mut ttp_writer) = split(ttp_stream);

        // Ask server's certificate and validate it by TTP
        let mut cert_req = Message::new(MessageOpcode::HandshakeStart, vec![]);
        send_message(&mut writer, &mut cert_req).await?;
        let response = receive_message(&mut reader).await?;
        let server_cert = Certificate::from_message(response).unwrap();
        let is_cert_valid = server_cert
            .validate_certificate(&mut ttp_reader, &mut ttp_writer)
            .await?;
        let mut ttp_stream = ttp_reader.unsplit(ttp_writer);
        ttp_stream.shutdown().await?;

        if !is_cert_valid {
            send_message(
                &mut writer,
                &mut Message {
                    op: MessageOpcode::CertificateRejected,
                    payload: vec![],
                },
            )
            .await?;
            let mut stream = reader.unsplit(writer);
            stream.shutdown().await?;

            return Err(io::Error::other("Certificate is not valid"));
        }

        println!("Server\'s certificate is valid");

        send_message(
            &mut writer,
            &mut Message {
                op: MessageOpcode::CertificateAccepted,
                payload: vec![],
            },
        )
        .await?;

        // Send the client's certificate to the server
        let request = receive_message(&mut reader).await?;
        self.cert
            .as_mut()
            .unwrap()
            .display_cert(request, &mut writer)
            .await?;

        // Check if the server accepted our certificate
        let server_resp = receive_message(&mut reader).await?;
        if server_resp.op != MessageOpcode::CertificateAccepted {
            let mut stream = reader.unsplit(writer);
            stream.shutdown().await?;
            return Err(io::Error::other("Handshake error"));
        }

        // At this point, we know the server's cert, and the server knows our cert
        // The server is supposed to send a message containing the symmetric key (bytes 0-15), and the IV for CBC (bytes 16-31)
        let symmetric_key_msg = receive_message(&mut reader).await?;
        let encrypted_symmetric_key = symmetric_key_msg.payload;
        let symmetric_key = self
            .keypair
            .private
            .decrypt(&BigUint::from_bytes_be(&encrypted_symmetric_key));

        let symmetric_key_bytes: [u8; AES_BLOCK_SIZE] =
            symmetric_key.to_bytes_be().try_into().unwrap();
        let symmetric_key_arr = GenericArray::from(symmetric_key_bytes);
        let cipher = Aes128::new(&symmetric_key_arr);

        // We now have a stream with the server, and a cipher under which to encrypt & decrypt messages
        self.peer_addr = Some(peer_addr);
        self.stream = Some((reader, writer));
        self.cipher = Some(cipher);

        Ok(())
    }

    // Listen for client
    pub async fn listen(
        &mut self,
        host: &String,
        port: u16,
        ttp_host: &String,
        ttp_port: u16,
    ) -> Result<(), io::Error> {
        let listener = TcpListener::bind(format!("{}:{}", host, port)).await?;

        let (stream, _) = listener.accept().await?;
        let peer_addr = stream.peer_addr().unwrap();
        let (mut reader, mut writer) = split(stream);

        // Receive the client's request which would like to get the server's certificate
        let request = receive_message(&mut reader).await?;
        self.cert
            .as_mut()
            .unwrap()
            .display_cert(request, &mut writer)
            .await?;

        // Check the client's response validating the server's certificate
        let client_resp = receive_message(&mut reader).await?;
        if client_resp.op != MessageOpcode::CertificateAccepted {
            let mut stream = reader.unsplit(writer);
            stream.shutdown().await?;
            return Err(io::Error::other("Handshake error"));
        }

        let ttp_stream = TcpStream::connect(format!("{}:{}", ttp_host, ttp_port)).await?;
        let (mut ttp_reader, mut ttp_writer) = split(ttp_stream);

        // Ask for the client's certificate and validate it by TTP
        let mut cert_req = Message::new(MessageOpcode::HandshakeStart, vec![]);
        send_message(&mut writer, &mut cert_req).await?;
        let response = receive_message(&mut reader).await?;
        let client_cert = Certificate::from_message(response).unwrap();
        let is_cert_valid = client_cert
            .validate_certificate(&mut ttp_reader, &mut ttp_writer)
            .await?;
        let mut ttp_stream = ttp_reader.unsplit(ttp_writer);
        ttp_stream.shutdown().await?;

        if !is_cert_valid {
            send_message(
                &mut writer,
                &mut Message {
                    op: MessageOpcode::CertificateRejected,
                    payload: vec![],
                },
            )
            .await?;
            let mut stream = reader.unsplit(writer);
            stream.shutdown().await?;

            return Err(io::Error::other("Certificate is not valid"));
        }

        send_message(
            &mut writer,
            &mut Message {
                op: MessageOpcode::CertificateAccepted,
                payload: vec![],
            },
        )
        .await?;

        // At this point, we know the client's cert and vice versa
        println!("Client\'s certificate is valid");

        // Generate a symmetric key
        let mut rng = ChaCha20Rng::from_entropy();
        let mut key = [0u8; AES_BLOCK_SIZE];
        rng.fill_bytes(&mut key);
        let mut iv = [0u8; AES_BLOCK_SIZE];
        rng.fill_bytes(&mut iv);
        // Encrypt the symmetric key under the client's public key
        let client_public = client_cert.public;
        let encrypted_key = client_public.encrypt(&BigUint::from_bytes_be(&key));
        let mut msg = Message {
            op: MessageOpcode::SymmetricKey,
            payload: encrypted_key.to_bytes_be(),
        };
        send_message(&mut writer, &mut msg).await?;

        let symmetric_key_arr = GenericArray::from(key);
        let cipher = Aes128::new(&symmetric_key_arr);

        self.peer_addr = Some(peer_addr);
        self.stream = Some((reader, writer));
        self.cipher = Some(cipher);

        Ok(())
    }

    pub async fn send_text(&mut self, text: String) -> Result<(), io::Error> {
        let ciphertext = encrypt(
            &mut text.as_bytes().to_vec(),
            self.cipher
                .as_mut()
                .expect("Connection Establishement failed"),
        );

        let mut msg = Message {
            op: MessageOpcode::Text,
            payload: ciphertext.into_iter().flatten().collect(),
        };
        if let Some((_, ref mut writer)) = &mut self.stream {
            send_message(writer, &mut msg).await?;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "No active connection",
            ));
        }

        Ok(())
    }

    pub async fn receive_text(&mut self) -> Result<String, io::Error> {
        let msg: Message;
        if let Some((ref mut reader, _)) = &mut self.stream {
            msg = receive_message(reader).await?;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "No active connection",
            ));
        }

        if msg.op != MessageOpcode::Text {
            return Err(io::Error::other(
                "Expected to find a text, but found another type of message",
            ));
        }

        let mut ciphertext = msg.payload;
        let plaintext_blocks = decrypt(
            &mut ciphertext,
            self.cipher
                .as_mut()
                .expect("Failed to establish connection"),
        );
        let plaintext =
            String::from_utf8(plaintext_blocks.into_iter().flatten().collect()).unwrap();

        Ok(plaintext)
    }
}

pub struct Certificate {
    name: String,
    public: PublicKey,
    signature: Vec<u8>,
}

impl Debug for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let signature = self
            .signature
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<String>();
        write!(
            f,
            "Certificate {{ name: {}, public.n: {}, public.e: {}, signature: {} }}",
            self.name, self.public.e, self.public.n, signature,
        )
    }
}

impl Certificate {
    fn from_message(msg: Message) -> Result<Certificate, io::Error> {
        if msg.op != MessageOpcode::CertificateShow {
            return Err(io::Error::other(
                "Expected a certificate, but received something else",
            ));
        }

        let payload = msg.payload;

        let name_length = u32::from_be_bytes(payload[0..4].try_into().unwrap());
        let name = String::from_utf8(payload[4..4 + name_length as usize].to_vec()).unwrap();
        let n = BigUint::from_bytes_be(
            &payload[4 + name_length as usize..4 + name_length as usize + N_SIZE],
        );
        // The length of the signature is always 256 bytes
        // Because we raise the digest (MD5 digest is always 128-bit = 16 bytes)
        // To the power of e=65537, and then take modulo n (2048 bits = 256 bytes)
        // We also pad the signature when sending it in case it is smaller than 256 bytes
        let signature = payload
            [4 + name_length as usize + N_SIZE..4 + name_length as usize + N_SIZE + SIGNATURE_SIZE]
            .to_vec();

        Ok(Certificate {
            name,
            public: PublicKey {
                e: RSA_EXP.into(),
                n,
            },
            signature,
        })
    }

    async fn display_cert(
        &self,
        msg: Message,
        writer: &mut WriteHalf<TcpStream>,
    ) -> Result<usize, io::Error> {
        if msg.op != MessageOpcode::HandshakeStart {
            return Err(io::Error::other(
                "Exepected a request for my certificate, but received something else",
            ));
        }

        let payload = self.to_bytes();
        let mut msg = Message {
            op: MessageOpcode::CertificateShow,
            payload,
        };
        Ok(send_message(writer, &mut msg).await?)
    }

    async fn validate_certificate(
        &self,
        reader: &mut ReadHalf<TcpStream>,
        writer: &mut WriteHalf<TcpStream>,
    ) -> Result<bool, io::Error> {
        let payload = self.to_bytes();

        let mut msg = Message {
            op: MessageOpcode::ValidateCertificate,
            payload,
        };
        send_message(writer, &mut msg).await?;

        let resp = receive_message(reader).await?;
        Ok(if resp.payload[0] == 1 { true } else { false })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let name_length = self.name.len() as u32;
        let name = &self.name;
        let n = pad_bigint(&self.public.n, 2048).to_bytes_be();
        let signature = &self.signature;

        let mut payload = Vec::with_capacity(4 + name.len() + n.len() + signature.len());
        payload.extend_from_slice(&name_length.to_be_bytes());
        payload.extend_from_slice(name.as_bytes());
        payload.extend_from_slice(&n);
        payload.extend_from_slice(signature);

        payload
    }
}

fn pad_bigint(num: &BigUint, target_bits: usize) -> BigUint {
    let mut bytes = num.to_bytes_be();
    let padding_bytes = (target_bits + 7) / 8 - bytes.len();
    bytes.resize(bytes.len() + padding_bytes, 0);
    BigUint::from_bytes_be(&bytes)
}
