/*
Byte-at-a-time ECB decryption (Simple)

Copy your oracle function to a new function that encrypts buffers under ECB
mode using a consistent but unknown key (for instance, assign a single random
key, once, to a global variable).

Now take that same function and have it append to the plaintext, BEFORE
ENCRYPTING, the following string:

Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK

Spoiler alert.

Do not decode this string now. Don't do it.

Base64 decode the string before appending it. Do not base64 decode the string
by hand; make your code do it. The point is that you don't know its contents.

What you have now is a function that produces:

AES-128-ECB(your-string || unknown-string, random-key)

It turns out: you can decrypt "unknown-string" with repeated calls to the
oracle function!

Here's roughly how:

    Feed identical bytes of your-string to the function 1 at a time --- start
    with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the block
    size of the cipher. You know it, but do this step anyway.

    Detect that the function is using ECB. You already know, but do this step
    anyways.

    Knowing the block size, craft an input block that is exactly 1 byte short
    (for instance, if the block size is 8 bytes, make "AAAAAAA"). Think about
    what the oracle function is going to put in that last byte position.

    Make a dictionary of every possible last byte by feeding different
    strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC",
    remembering the first block of each invocation.

    Match the output of the one-byte-short input to one of the entries in
    your dictionary. You've now discovered the first byte of unknown-string.

    Repeat for the next byte.

Congratulations.

This is the first challenge we've given you whose solution will break real
crypto. Lots of people know that when you encrypt something in ECB mode, you
can see penguins through it. Not so many of them can decrypt the contents of
those ciphertexts, and now you can. If our experience is any guideline, this
attack will get you code execution in security tests about once a year.
*/

#[macro_use]
extern crate lazy_static;
extern crate challenge_10;
extern crate challenge_11;

use challenge_10::*;
use challenge_11::*;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::io;
use std::io::prelude::*;

lazy_static! {
    static ref SECRET_KEY: Vec<u8> = random_aes_key();
}

pub fn oracle(input: &[u8]) -> Vec<u8> {
    let mut unknown_bytes = hex_to_bytes(&base_64_to_hex(
        &fs::read_to_string("unknown_string.txt").expect("Unable to read file"),
    ));
    let mut to_encrypt = vec![0; 17];
    to_encrypt.append(&mut input.to_vec());
    to_encrypt.append(&mut unknown_bytes);
    encrypt_aes_128_ecb(&to_encrypt, &bytes_to_string(&SECRET_KEY))
}

pub fn shared_bytes(a: &[u8], b: &[u8], skip: usize) -> usize {
    a.chunks(2)
        .zip(b.chunks(2))
        .skip(skip)
        .take_while(|(a, b)| a == b)
        .count()
        * 2
}

pub fn decrypt_text_from_oracle(oracle: &Fn(&[u8]) -> Vec<u8>) -> Vec<u8> {
    /*
    First we need to know how many bytes of this content will remain the same
    even when we start interjecting stuff?
    */
    let no_padding = oracle(&[]);
    let one_padding = oracle(&[0x61]);

    let before_padding = shared_bytes(&no_padding, &one_padding, 0);

    let mut padding_size = 1;
    let mut last_output: Vec<u8> = Vec::new();

    // When we have passed end of the block that we are inserting into it will
    // stop changing. This is our initial offset between where our padding is
    // going and the end of the block. However, we don't know the block size
    // until the block _after that_ stops changing.
    let mut block_size = 0;
    let mut bytes_to_end_of_block = 0;
    while block_size == 0 {
        let padding: Vec<u8> = (0..padding_size).map(|_| 0x61).collect();
        let oracle_output = oracle(&padding);

        // Number of bytes shared between out latest output and the output
        // before that, ignoring the stuff that we know never changes
        let common_bytes = shared_bytes(&last_output, &oracle_output, before_padding);

        if common_bytes > 0 {
            // The block we are inserting into has stopped changing.
            if bytes_to_end_of_block == 0 {
                bytes_to_end_of_block = padding_size - before_padding - 1;
            } else {
                block_size = common_bytes;
                // Here's a thing that can happen - we were inserting to the
                // beginning of the string, and we found out that we were X
                // bytes from the end of the block, but we didn't know how big
                // the block was yet. It turns out the block is X bytes big, so
                // actually we were at the end of the block when we started. In
                // other words, we are zero bytes from the end of the block we
                // are inserting into.
                if bytes_to_end_of_block == block_size {
                    bytes_to_end_of_block = 0;
                }
            }
        } else if padding_size > 512 {
            panic!("Can't find a stable block size");
        } else {
            last_output = oracle_output.to_vec();
            padding_size += 1;
        }
    }
    println!("Found block size: {}", block_size);
    println!("Block offset size: {}", bytes_to_end_of_block);

    // Now that we know the block size, it should be easy to see if we are
    // dealing with ECB, because a repeated block in the input will result in a
    // repeated block in the output Because we might not know exactly where the
    // block begins and ends we should use a 3x block padding in order to ensure
    // a perfectly repeated block.
    //==========================================================================
    // OK, actually, I've rewritten portions of this function so we *always*
    // know at this point how big the blocks are and exactly how much
    // information we would have to pad in order to pick up ECB, but all that
    // that would save us is a block_size amount of memory a single time, and
    // that's not worth it. I'm leaving this as it is.
    let contrived_triple_block: Vec<u8> = (0..block_size * 3).map(|_| 0x61).collect();
    let oracle_output = oracle(&contrived_triple_block);
    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    let mut ecb = false;
    for chunk in oracle_output.chunks(block_size) {
        if seen.contains(chunk) {
            println!("Confirmed ECB. Continuing to padding attack.");
            ecb = true;
            break;
        }
        seen.insert(chunk.to_vec());
    }

    if !ecb {
        panic!("It looks like we aren't in ECB mode, a padding attack won't work.");
    }

    // Now for the actual decryption. We'll use a fixed padding that is 1 byte
    // short of the block size, and we'll map over all of UTF-8 to get the
    // outcomes of the oracle for each codepoint in that last position. Once we
    // have that, we can iterate over the bytes in the cyphered text, and use
    // the map we've built up to figure out their de-encrypted form.
    let mut deciphered: Vec<u8> = Vec::new();
    // We add a block size here so that even if we are already at the end of a
    // block we put in the right amount of padding. There is a corner case which
    // is if we *start* at 1 from the end of the block. In that case, we don't
    // need *any* padding to start with.
    let mut padding: Vec<u8> = match bytes_to_end_of_block {
        1 => (0..0),
        _ => (0..bytes_to_end_of_block + block_size - 1),
    }
    .map(|_| 0x61)
    .collect();
    let mut beginning_of_block = before_padding + bytes_to_end_of_block;

    loop {
        let mut output_to_char: HashMap<String, u8> = HashMap::new();
        for i in 0..128 {
            let mut combined = padding.clone();
            combined.append(&mut deciphered.clone());
            combined.push(i);
            let relevant_output = &oracle(&combined)
                [beginning_of_block..beginning_of_block + block_size - 1]
                .to_vec();
            output_to_char
                .entry(bytes_to_hex_string(relevant_output))
                .or_insert(i);
        }
        let oracle_output = oracle(&padding);
        let next = match output_to_char.get(&bytes_to_hex_string(
            &oracle_output[beginning_of_block..beginning_of_block + block_size - 1],
        )) {
            Some(c) => c,
            None => return deciphered,
        };
        if padding.is_empty() {
            //   When we reach the end of the block we need to start using the
            //   next available block for the attack. For instance, decoding the
            //   alphabet encrypted under a 4-byte cypher might look like this:
            //   XXX?|????
            //   XXA?|????
            //   XAB?|????
            //   ABC?|????
            //   XXXA|BCD?
            //   Now instead of varying the character in the final block spot of
            //   our first block, we vary the character in the final block spot
            //   of our second block. This goes on until we've decrypted the
            //   whole message.
            beginning_of_block += block_size;
            padding = (0..block_size - 1).map(|_| 0x61).collect();
        } else {
            padding.pop();
        }
        deciphered.push(*next);
        print!("{}", *next as char);
        io::stdout().flush().unwrap();
    }
}
