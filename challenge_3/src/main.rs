use std::fs;

extern crate challenge_2;
extern crate challenge_3;
use challenge_2::*;
use challenge_3::*;

fn main() {
    let plaintext = fs::read_to_string("plaintext.txt").expect("Unable to read file");

    for _ in 0..100 {
        println!(
            "{}",
            count_repeating_blocks_with_offsets(&encryption_oracle(plaintext.as_bytes()))
        );
    }
}
