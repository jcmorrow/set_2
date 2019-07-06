extern crate challenge_10;
use challenge_10::*;

use std::fs::File;
use std::io::{BufReader, Read};

fn main() {
    let file = File::open("10.txt").unwrap();
    let mut buf = BufReader::new(file);
    let mut encrypted_base_64 = String::new();
    buf.read_to_string(&mut encrypted_base_64).unwrap();

    let key = "YELLOW SUBMARINE";

    let encrypted_hex = hex_to_bytes(&base_64_to_hex(&encrypted_base_64));
    let encrypted_block = encrypted_hex[0..16].to_owned();
    let encrypted_block_2 = encrypted_hex[16..32].to_owned();
    println!("{:?}", encrypted_block);
    println!("{:?}", encrypted_block_2);

    let decrypted = decrypt_one_block_aes_128_ecb(&encrypted_block, key.as_bytes());
    let decrypted_2 = xor(
        &decrypt_one_block_aes_128_ecb(&encrypted_block_2, key.as_bytes()),
        &encrypted_block,
    );

    println!("Decrypted: {:?}", bytes_to_string(&decrypted));
    println!("Decrypted: {:?}", bytes_to_string(&decrypted_2));

    let encrypted = encrypt_aes_128_ecb(&decrypted, key);
    let encrypted_2 = encrypt_aes_128_ecb(&xor(&encrypted, &decrypted_2), key);

    println!("Encrypted Again: \t{:?}", encrypted);
    println!("Encrypted Again: \t{:?}", encrypted_2);

    let tailing_junk = vec![
        96, 250, 54, 112, 126, 69, 244, 153, 219, 160, 242, 91, 146, 35,
    ];

    let encrypted_2 = encrypt_aes_128_ecb(&[0x00; 16], key);
    println!("maybe tailing junk: \t{:?}", encrypted_2);

    println!("{:?}", &tailing_junk);
}
