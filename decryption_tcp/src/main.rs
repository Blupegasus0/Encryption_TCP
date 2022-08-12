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

const BUFFER_SIZE: usize = 1024 + 16;

fn main() -> Result<(), anyhow::Error> {
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 19];

    // USES EMPTY KEY/NONCE UNSECURE

    //OsRng.fill_bytes(&mut key);
    //OsRng.fill_bytes(&mut nonce);

    let output_file_path = "test.decrypt";

    decrypt_large_file(&output_file_path, &key, &nonce,)?;

    Ok(())
}


fn decrypt_large_file(
    output_path: &str,
    key: &[u8; 32],
    nonce: &[u8; 19],
) -> Result<(), anyhow::Error> {
    // private
    let ip_addr = "192.168.100.227:8081";

    // create listener and bind it to ip_addr port 8081
    let listener = TcpListener::bind(ip_addr).unwrap();
    let mut buffer = [0; BUFFER_SIZE];

    // Initialize decryption variables 
    let aead = XChaCha20Poly1305::new(key.as_ref().into());
    let mut stream_decryptor = stream::DecryptorBE32::from_aead(aead, nonce.as_ref().into());

    // Use stream as source
    let mut output_file = File::create(output_path)?;

    // listen for incoming connections
    for stream in listener.incoming() {
        let mut stream = stream.unwrap();
    
        // test to see how many times to loop iterates
        println!("looped");

        // Read in buffer 
        let read_count = stream.read(&mut buffer).unwrap();

        // Shows the number of bytes read
        println!("{}", read_count);

        if read_count == BUFFER_SIZE { 
            // If the buffer is full then expect more packets
            let plaintext = stream_decryptor
                .decrypt_next(buffer.as_slice())
                .map_err(|e| anyhow!("Decrypting large file 1: {}", e))?;

            output_file.write(&plaintext)?;
        } else if read_count == 0 {
            // If there is no more data ... end
            break;
        } else {
            // If the buffer is neither empty nor full then this is the last packet
            let plaintext = stream_decryptor
                .decrypt_last(&buffer[..read_count])
                .map_err(|e| anyhow!("Decrypting large 2: {}", e))?;

            output_file.write(&plaintext)?;
            break;
        }

    }

    Ok(())
}


