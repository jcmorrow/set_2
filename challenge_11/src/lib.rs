/*
An ECB/CBC detection oracle

Now that you have ECB and CBC working:

Write a function to generate a random AES key; that's just 16 random bytes.

Write a function that encrypts data under an unknown key --- that is, a function that generates a
random key and encrypts under it.

The function should look like:

encryption_oracle(your-input)
=> [MEANINGLESS JIBBER JABBER]

Under the hood, have the function append 5-10 bytes (count chosen randomly) before the plaintext
and 5-10 bytes after the plaintext.

Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC the other half (just
use random IVs each time for CBC). Use rand(2) to decide which to use.

Detect the block cipher mode the function is using each time. You should end up with a piece of
code that, pointed at a block box that might be encrypting ECB or CBC, tells you which one is
happening.
*/

extern crate challenge_10;
extern crate rand;

use challenge_10::*;
use rand::Rng;
use std::collections::HashMap;

pub fn random_aes_key() -> Vec<u8> {
    (0..16).map(|_| random_utf8_byte()).collect()
}

pub fn random_utf8_byte() -> u8 {
    rand::thread_rng().gen_range(0, 128)
}

#[allow(dead_code)]
fn random_padding(min: usize, max: usize) -> Vec<u8> {
    (0..rand::thread_rng().gen_range(min, max))
        .map(|_| 0x04)
        .collect()
}

#[allow(dead_code)]
fn pad_five_to_ten_randomly(input: &[u8]) -> Vec<u8> {
    let mut new: Vec<u8> = Vec::new();
    new.append(&mut random_padding(5, 10));
    new.append(&mut input.to_vec());
    new.append(&mut random_padding(5, 10));
    new
}

pub fn encryption_oracle(input: &[u8]) -> Vec<u8> {
    let key = random_aes_key();
    match rand::thread_rng().gen_range(0, 2) {
        0 => {
            println!("ECB");
            encrypt_aes_128_ecb(input, &bytes_to_string(&key))
        }
        1 => {
            println!("CBC");
            encrypt_aes_128_cbc(input, &bytes_to_string(&key))
        }
        _ => panic!("what the hell? Why is our random not a 1 or 0?"),
    }
}

pub fn count_repeating_bytes(input: &[u8]) -> u32 {
    let mut string_counts: HashMap<u8, u32> = HashMap::new();
    for byte in input {
        let current_count = string_counts.entry(*byte).or_insert(0);
        *current_count += 1;
    }
    string_counts.values().fold(0, |mut acc, entry| {
        if *entry > 1 {
            acc += *entry;
        }
        acc
    })
}

// If this returns anything higher than 0 then our blackbox is most likely running in ECB mode.
pub fn count_repeating_blocks_with_offsets(input: &[u8]) -> u32 {
    (0..16)
        .map(|i| count_repeating_blocks(&input[i..].to_vec()))
        .max()
        .unwrap()
}

pub fn count_repeating_blocks(input: &[u8]) -> u32 {
    let mut string_counts: HashMap<String, u32> = HashMap::new();
    for block in input.chunks(16) {
        let current_count = string_counts
            .entry(bytes_to_hex_string(&block))
            .or_insert(0);
        *current_count += 1;
    }
    string_counts.values().fold(0, |mut acc, entry| {
        if *entry > 1 {
            acc += *entry;
        }
        acc
    })
}
