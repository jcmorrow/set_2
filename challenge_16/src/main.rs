#[macro_use]
extern crate lazy_static;

extern crate challenge_10;
extern crate challenge_11;
extern crate challenge_12;

use challenge_10::*;
use challenge_11::*;
#[allow(unused_imports)]
use challenge_12::*;
use std::panic;

lazy_static! {
    static ref SECRET_KEY: Vec<u8> = random_aes_key();
}
fn main() {
    assert!(!reverse_oracle(&oracle(b"Hello, ;role=admin; world!")));

    // I'm calling this putty because it's just a bunch of padding that we are going to shape into
    // our desired string. The first block is the block which we will be editing the cyphertext of.
    // That will XOR with the plaintext of the next block to create the decrypted text we want. I
    // still don't understand if it's possible to ensure that your whole decrypted text is ascii
    // using this method, because changing even a single bit of a cypher text almost ensures that
    // it will come out as garbage once it's been decrypted by AES, but I can't think of a way of
    // fixing that right now.
    let putty = vec!['a' as u8; 32];
    let encrypted = oracle(&putty);
    let mut edits = xor(b"aaaaaaaaaaaaaaaa", b";admin=true&a=ik");
    let mut full_edits = vec![0; 32];
    full_edits.append(&mut edits);
    full_edits.append(&mut vec![0; 32]);

    let doctored = xor(&encrypted, &full_edits);

    let result = panic::catch_unwind(|| {
        println!("{}", &reverse_oracle(&doctored));
    });
    if result.is_ok() {
        println!("SUCCESS: {}", bytes_to_hex_string(&doctored));
    }
}

fn hex_string_spaced(input: &[u8]) -> String {
    bytes_to_hex_string(input)
        .as_bytes()
        .to_vec()
        .chunks(2)
        .map(|x| String::from_utf8(x.to_vec()).unwrap())
        .collect::<Vec<String>>()
        .join(" ")
}

fn make_comment(comment: &str) -> String {
    let mut result = String::from("comment1=cooking%20MCs;userdata=");
    let filtered = String::from(comment)
        .replace(";", "\";\"")
        .replace("=", "\"=\"");
    result.push_str(&filtered);
    result.push_str(";comment2=%20like%20a%20pound%20of%20bacon");
    result
}

fn oracle(comment: &[u8]) -> Vec<u8> {
    encrypt_aes_128_cbc(
        &make_comment(&bytes_to_string(comment)).as_bytes(),
        &bytes_to_string(&SECRET_KEY),
    )
}

fn reverse_oracle(comment: &[u8]) -> bool {
    let decrypted = decrypt_aes_128_cbc(&comment, &bytes_to_string(&SECRET_KEY));
    for chunk in decrypted.chunks(16) {
        if !chunk.to_vec().iter().any(|x| *x > 128 as u8) {
            dbg!(bytes_to_string(chunk));
        }
    }
    bytes_to_string(&decrypted).contains("admin=true")
}
