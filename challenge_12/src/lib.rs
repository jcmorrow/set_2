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
use std::fs;

lazy_static! {
    static ref SECRET_KEY: Vec<u8> = random_aes_key();
}

pub fn oracle(input: &[u8]) -> Vec<u8> {
    let mut unknown_bytes = hex_to_bytes(&base_64_to_hex(
        &fs::read_to_string("unknown_string.txt").expect("Unable to read file"),
    ));
    let mut to_encrypt = input.to_vec();
    to_encrypt.append(&mut unknown_bytes);
    encrypt_aes_128_ecb(&to_encrypt, &bytes_to_string(&SECRET_KEY))
}
