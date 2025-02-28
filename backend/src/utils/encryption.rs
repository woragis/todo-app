use aes::Aes128;
use aes::cipher::{BlockEncrypt, BlockDecrypt, KeyInit};
use cipher::generic_array::GenericArray;
use log::debug;
use openssl::error::Error;
use openssl::sha::Sha512;
// use aes_gcm::{Aes256Gcm, Key, Nonce, aead::Aead};
// use rand::Rng;

pub fn sha_encrypt_string(payload: String) -> Result<String, Error> {
    debug!("Encrypting with sha...");
    let key = "banana";
    let mut my_sha = Sha512::new();
    my_sha.update(key.as_bytes());
    my_sha.update(payload.as_bytes());

    let result = hex::encode(my_sha.finish());

    Ok(result)
}

pub fn aes_encrypt_string(payload: String) -> Vec<u8> {
    debug!("Encrypting with aes...");
    let key=GenericArray::from([0u8;16]);
    let cipher = Aes128::new(&key);

    let blocks: Vec<_> = payload.as_bytes().chunks(16).map(|chunk| {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk); // copy data and pad if necessary
        let mut block = GenericArray::from(block);
        cipher.encrypt_block(&mut block);
        block.to_vec()
    }).flatten().collect();

    blocks
}

pub fn aes_decrypt_string(payload: Vec<u8>) -> String {
    debug!("Decrypting aes...");
    let key=GenericArray::from([0u8;16]);
    let cipher = Aes128::new(GenericArray::from_slice(&key));

    let decrypted_bytes: Vec<u8> = payload.chunks(16).map(|chunk| {
        let mut block: GenericArray<u8, _> = GenericArray::clone_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        block.to_vec()
    }).flatten().collect();

    String::from_utf8_lossy(&decrypted_bytes).trim_matches('\0').to_string()
}

use hex;

// fn encrypt_email(email: &str, key: &[u8]) -> (String, String) {
//     let cipher = Aes256Gcm::new(Key::from_slice(key));

//     // Generate a random nonce (12 bytes)
//     let nonce_bytes: [u8; 12] = rand::thread_rng().gen();
//     let nonce = Nonce::from_slice(&nonce_bytes);

//     // Encrypt email
//     let ciphertext = cipher.encrypt(nonce, email.as_bytes()).expect("encryption failed");

//     // Return Base64-encoded encrypted email + nonce
//     (
//         base64::encode(ciphertext),
//         base64::encode(nonce_bytes),
//     )
// }

// fn decrypt_email(encrypted_email: &str, nonce: &str, key: &[u8]) -> String {
//     let cipher = GenericArray::from("banana");
    
//     let decrypted = cipher.decrypt(
//         Nonce::from_slice(&base64::decode(nonce).expect("Invalid nonce")), 
//         &base64::decode(encrypted_email).expect("Invalid ciphertext")[..]
//     ).expect("decryption failed");

//     String::from_utf8(decrypted).expect("Invalid UTF-8")
// }

