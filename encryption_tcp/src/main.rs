use anyhow::anyhow;    
use chacha20poly1305::{    
    aead::{stream, Aead, NewAead},                                                                                                                                                            
    XChaCha20Poly1305,    
};    
use rand::{Rng, RngCore, rngs::OsRng};    
use std::{    
    fs::{self, File},    
    io::{Read, Write},    
};    
use std::net::{TcpListener, TcpStream};

fn main() -> Result<(), anyhow::Error> {
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 19];

    

    OsRng.fill_bytes(&mut key);
    OsRng.fill_bytes(&mut nonce);

    let file_path = "test.txt";
    let encrypted_file_path = "test.encrypt";
    let output_file_path = "test.decrypt";

    // Replace encrypted_file_path in server with the tcp stream listener
    // 


    encrypt_large_file(&file_path, &encrypted_file_path, &key, &nonce,)?;


    Ok(())
}

fn encrypt_large_file(
    source_file_path: &str,
    output_path: &str,
    key: &[u8; 32],
    nonce: &[u8; 19],
) -> Result<(), anyhow::Error> {

    // Connect to the stream
    let mut stream = TcpStream::connect("localhost:8081").unwrap();

    // Create message as bytes
    let msg = b"short message";

    //  Write message to the stream
    stream.write(msg).unwrap();

    
    // ENCRYPTION
    let aead = XChaCha20Poly1305::new(key.as_ref().into());
    let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());

    const BUFFER_SIZE: usize = 1024;
    let mut buffer = [0u8; BUFFER_SIZE];

    let mut source_file = File::open(source_file_path)?;
    let mut output_file = File::create(output_path)?;

    loop {
        let read_count = source_file.read(&mut buffer)?;

        if read_count == BUFFER_SIZE {
            let ciphertext = stream_encryptor
                .encrypt_next(buffer.as_slice())
                .map_err(|e| anyhow!("Encryping large file: {}", e))?;
            
            output_file.write(&ciphertext)?;
        } else {
            let ciphertext = stream_encryptor
                .encrypt_last(&buffer[..read_count])
                .map_err(|e| anyhow!("Encryping large file: {}", e))?;
            
            output_file.write(&ciphertext)?;
            break;
        }
    }

    Ok(())
}



