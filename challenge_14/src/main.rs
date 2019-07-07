#[macro_use]
extern crate lazy_static;
extern crate rand;

extern crate challenge_11;
extern crate challenge_12;

use challenge_11::*;
use challenge_12::*;
use rand::Rng;

lazy_static! {
    static ref PREPENDED: Vec<u8> = random_bytes_1_to_128();
}

pub fn random_bytes_1_to_128() -> Vec<u8> {
    let len = rand::thread_rng().gen_range(0, 128);
    (0..len).map(|_| random_utf8_byte()).collect()
}

fn main() {
    decrypt_text_from_oracle(&prepending_oracle);
}

fn prepending_oracle(plaintext: &[u8]) -> Vec<u8> {
    let mut prepended = PREPENDED.clone();
    prepended.append(&mut plaintext.to_vec());
    oracle(&prepended)
}
