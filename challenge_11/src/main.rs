use std::fs;

extern crate challenge_10;
extern crate challenge_11;
use challenge_10::*;
use challenge_11::*;

fn main() {
    let plaintext = fs::read_to_string("plaintext.txt").expect("Unable to read file");

    for _ in 0..100 {
        println!(
            "{}",
            count_repeating_blocks_with_offsets(&encryption_oracle(plaintext.as_bytes()))
        );
    }
}
