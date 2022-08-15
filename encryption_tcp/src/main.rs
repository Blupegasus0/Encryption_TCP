use anyhow::anyhow;
use chacha20poly1305::{
    aead::{stream, Aead, NewAead},
    XChaCha20Poly1305,
};
use rand::{rngs::OsRng, Rng, RngCore};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::{
    fs::{self, File},
    io::{Read, Write},
};

const BUFFER_SIZE: usize = 1024;

fn main() -> Result<(), anyhow::Error> {
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 19];

    // USES EMPTY KEY/NONCE UNSECURE

    //OsRng.fill_bytes(&mut key);
    //OsRng.fill_bytes(&mut nonce);

    let file_path = "test.txt";

    encrypt_large_file(&file_path, &key, &nonce)?;

    Ok(())
}

fn encrypt_large_file(
    source_file_path: &str,
    key: &[u8; 32],
    nonce: &[u8; 19],
) -> Result<(), anyhow::Error> {
    // Initialize encryption variables
    let aead = XChaCha20Poly1305::new(key.as_ref().into());
    let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());

    let mut buffer = [0u8; BUFFER_SIZE];

    let mut source_file = File::open(source_file_path)?;

    // public
    //let socket = "173.255.185.209:8081";
    // private
    //let socket = "192.168.100.227:8081";
    // ipv6
    let ipv6 = "fe80::e122:f87:d8ca:7a84";
    let port = 8081;
    let socket = (ipv6, port).to_socket_addrs();

    /*let mut socket = std::net::SocketAddrV6::new(
        std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0xe122, 0xf87, 0xd8ca, 0x7a84),
        8080,
        0,
        0,
    );*/

    loop {
        let read_count = source_file.read(&mut buffer)?;

        println!("{}", read_count);

        if read_count == BUFFER_SIZE {
            // If the buffer is full then expect more data
            let ciphertext = stream_encryptor
                .encrypt_next(buffer.as_slice())
                .map_err(|e| anyhow!("Encryping large file: {}", e))?;

            // Connect to the stream
            let mut stream = TcpStream::connect(socket).unwrap();
            //  Write message to the stream
            stream.write(&ciphertext).unwrap();
        } else {
            // If the buffer is not full then send the ending packet
            let ciphertext = stream_encryptor
                .encrypt_last(&buffer[..read_count])
                .map_err(|e| anyhow!("Encryping large file: {}", e))?;

            // Connect to the stream
            let mut stream = TcpStream::connect(socket).unwrap();
            //  Write message to the stream
            stream.write(&ciphertext).unwrap();

            break;
        }
    }

    Ok(())
}
