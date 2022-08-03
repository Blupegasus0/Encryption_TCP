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


    decrypt_large_file(&encrypted_file_path, &output_file_path, &key, &nonce,)?;


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


fn decrypt_large_file(
    encrypted_file_path: &str,
    output_path: &str,
    key: &[u8; 32],
    nonce: &[u8; 19],
) -> Result<(), anyhow::Error> {
    // create listener and bind it to localhost port 7878
    let listener = TcpListener::bind("localhost:8081").unwrap();
    let mut buffer = [0; BUFFER_SIZE];

    // listen for incoming connections
    for stream in listener.incoming() {
        let mut stream = stream.unwrap();

        // Read in buffer 
        stream.read(&mut buffer).unwrap();
        println!("{}", String::from_utf8_lossy(&buffer));
    }
    
    // DECRYPTION 
    let aead = XChaCha20Poly1305::new(key.as_ref().into());
    let mut stream_decryptor = stream::DecryptorBE32::from_aead(aead, nonce.as_ref().into());

    const BUFFER_SIZE: usize = 1024 + 16;
    let mut buffer = [0u8; BUFFER_SIZE];

    let mut encrypted_file = File::open(encrypted_file_path)?;
    let mut output_file = File::create(output_path)?;

    loop {
        let read_count = encrypted_file.read(&mut buffer)?;

        if read_count == BUFFER_SIZE { 
            let plaintext = stream_decryptor
                .decrypt_next(buffer.as_slice())
                .map_err(|e| anyhow!("Decrypting large file: {}", e))?;

            output_file.write(&plaintext)?;
        } else if read_count == 0 {
            break;
        } else {
            let plaintext = stream_decryptor
                .decrypt_last(&buffer[..read_count])
                .map_err(|e| anyhow!("Decrypting large: {}", e))?;

            output_file.write(&plaintext)?;
            break;
        }

    }

    Ok(())
}


