#[macro_use]
extern crate lazy_static;
use std::collections::HashMap;

extern crate challenge_10;
extern crate challenge_11;
extern crate challenge_12;

use challenge_10::*;
use challenge_11::*;

lazy_static! {
    static ref SECRET_KEY: Vec<u8> = random_aes_key();
}

fn main() {
    // I thought originally that this task was asking me to decrypt the user
    // profile as the attacker, without knowing what it was ahead of time. I
    // don't actually think that's required anymore. What I *think* it's asking
    // is for you to copy and paste some blocks of ciphertext *which you know
    // the plaintext to* to make a ciphertext that contains something that your
    // original ones never said.

    // So, let's see here:
    // email=&uid=10&role=user
    // 0123456789ABCDEF|0123456789ABCDEF|0123456789ABCDEF
    // We want our last block to be
    // admin00000000000

    // We can get any 16 byte ciphertext that doesn't include our special
    // characters by putting in 10 pads followed by 16 ordinary bytes we want:
    // email=XXXXXXXXXX|16_BYTES_WE_WANT|&uid=10&role=user
    //       ^   10    ^
    // Let's give it a shot!
    let plain = "YELLOW SUBMARINE".as_bytes();
    let mut email: Vec<u8> = (0..10).map(|_| 0x04).collect();
    email.append(&mut plain.to_vec());

    let encrypted = escaping_oracle(&email)[16..32].to_vec();

    println!(
        "{}",
        bytes_to_string(&decrypt_one_block_aes_128_ecb(&encrypted, &SECRET_KEY))
    );

    // And, lastly, we want that &role=to be at the end of the second block
    // email=XXXXXXXXXX|XXX&uid=10&role=|admin
    //       ^     13     ^
    // So, we need a thirteen character email:
    // allurbsrblng2 ought to work
    let mut first_two_blocks = escaping_oracle("allurbsrblng2".as_bytes())[0..32].to_vec();
    let mut email_padding_for_admin: Vec<u8> = (0..10).map(|_| 0x04).collect();
    email_padding_for_admin.append(&mut "admin".as_bytes().to_vec());
    email_padding_for_admin.append(&mut [0; 11].to_vec());
    let mut last_block = escaping_oracle(&email_padding_for_admin)[16..32].to_vec();
    first_two_blocks.append(&mut last_block);
    println!("{:?}", &reverse_oracle(&first_two_blocks));
}

fn profile_for(email: &str) -> String {
    let stripped_email = String::from(email).replace("=", "").replace("&", "");
    vec!["email=", &stripped_email, "&uid=10&role=user"].join("")
}

#[allow(dead_code)]
fn generate_cookie(cookie: HashMap<String, String>) -> String {
    let pairs = cookie
        .iter()
        .map(|(key, value)| {
            let mut s = String::new();
            s.push_str(&key);
            s.push('=');
            s.push_str(&value);
            s
        })
        .collect::<Vec<String>>();
    pairs.join("&")
}

#[allow(dead_code)]
fn parse_cookie(cookie: &str) -> HashMap<String, String> {
    println!("{}", &cookie);
    let mut parsed: HashMap<String, String> = HashMap::new();
    for key_val in String::from(cookie).split('&') {
        let mut split_by_equal = key_val.split('=').take(2).collect::<Vec<&str>>();
        let value = split_by_equal.pop().unwrap();
        let key = split_by_equal.pop().unwrap();
        parsed.insert(String::from(key), String::from(value));
    }
    parsed
}

#[allow(dead_code)]
fn swallowing_oracle(email_address: &[u8]) -> Vec<u8> {
    let email_string = String::from_utf8(email_address.to_vec()).unwrap();
    encrypt_aes_128_ecb(
        &profile_for(&email_string).as_bytes(),
        &bytes_to_string(&SECRET_KEY),
    )
}

#[allow(dead_code)]
fn escaping_oracle(email_address: &[u8]) -> Vec<u8> {
    let email_string = String::from_utf8(email_address.to_vec()).unwrap();
    encrypt_aes_128_ecb(
        &profile_for(&email_string).as_bytes(),
        &bytes_to_string(&SECRET_KEY),
    )
}

#[allow(dead_code)]
fn reverse_oracle(encrypted_cookie: &[u8]) -> HashMap<String, String> {
    parse_cookie(&bytes_to_string(&decrypt_aes_128_ecb(
        &encrypted_cookie,
        &bytes_to_string(&SECRET_KEY),
    )))
}
