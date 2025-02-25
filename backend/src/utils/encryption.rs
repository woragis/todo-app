use aes::Aes128;
use aes::cipher::{BlockEncrypt, BlockDecrypt, KeyInit};
use cipher::generic_array::GenericArray;
use openssl::error::Error;
use openssl::sha::Sha512;

pub fn sha_encrypt_string(payload: String) -> Result<String, Error> {
    let key = "banana";
    let mut my_sha = Sha512::new();
    my_sha.update(key.as_bytes());
    my_sha.update(payload.as_bytes());

    let result = hex::encode(my_sha.finish());

    Ok(result)
    // let response_string = format!("Input: {}\nSha: {}", payload, result);
    // Ok(HttpResponse::Ok().body(response_string))
}


// pub async fn aes_string(payload: String) -> Result<HttpResponse, Error> {
//     let my_encrypted = aes_encrypt_string(payload.clone());
//     let encrypted_len = &my_encrypted.len();
//     let my_decrypted = aes_decrypt_string(my_encrypted.clone());
//     let decrypted_len = &my_decrypted.len();


//     let response_string = format!("Input: {} - len: {}\nEncrypted: {:?} - len: {}\nDecrypted: {:?} - len: {}\n", payload.clone(), &payload.clone().len(), &my_encrypted, encrypted_len, &my_decrypted, decrypted_len);
//     Ok(HttpResponse::Ok().body(response_string))
// }


fn aes_encrypt_string(payload: String) -> Vec<u8> {
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

fn aes_decrypt_string(payload: Vec<u8>) -> String {
    let key=GenericArray::from([0u8;16]);
    let cipher = Aes128::new(GenericArray::from_slice(&key));

    let decrypted_bytes: Vec<u8> = payload.chunks(16).map(|chunk| {
        let mut block: GenericArray<u8, _> = GenericArray::clone_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        block.to_vec()
    }).flatten().collect();

    String::from_utf8_lossy(&decrypted_bytes).trim_matches('\0').to_string()
}

