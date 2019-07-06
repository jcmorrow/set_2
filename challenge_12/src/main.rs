use challenge_10::*;
use challenge_11::*;
use challenge_12::*;
use std::collections::HashMap;
use std::io;
use std::io::prelude::*;

fn main() -> Result<(), std::io::Error> {
    // Who needs to know the key ahead of time?
    let unknown_key = random_aes_key();

    let mut block_size = 4;
    let mut last_output: Vec<u8> = Vec::new();

    // Find the key size. The first block of bytes will stop changing once we
    // exceed it, and it's almost certainly a multiple of 2.
    loop {
        let mut padding: Vec<u8> = Vec::new();
        for _ in 0..block_size {
            padding.push(0x04);
        }
        let oracle_output = oracle(&padding, &unknown_key);

        let common_bytes = oracle_output
            .chunks(2)
            .zip(last_output.chunks(2))
            .take_while(|(a, b)| a == b)
            .count();

        if common_bytes > 2 {
            block_size = common_bytes * 2;
            break;
        } else if block_size > 256 {
            panic!("Can't find a stable block size");
        } else {
            last_output = oracle_output.to_vec();
            block_size += 2;
        }
    }
    println!("Found key size: {}", block_size);

    // Now that we know the key size, it should be easy to see if we are dealing with ECB, because
    // a repeated block in the input will result in a repeated block in the output
    let contrived_double_block: Vec<u8> = (0..block_size * 2).map(|_| 0x04).collect();
    let oracle_output = oracle(&contrived_double_block, &unknown_key);
    if oracle_output[0..block_size] == oracle_output[block_size..block_size * 2] {
        println!("Confirmed ECB. Continuing to padding attack.");
    } else {
        panic!("It looks like we aren't in ECB mode, a padding attack won't work.");
    }

    // Now for the actual decryption. We'll use a fixed padding that is 1 byte short of the key
    // size, and we'll map over all of UTF-8 to get the outcomes of the oracle for each codepoint
    // in that last position. Once we have that, we can iterate over the bytes in the cyphered
    // text, and use the map we've built up to figure out their de-encrypted form.
    let mut deciphered: Vec<u8> = Vec::new();
    let mut padding: Vec<u8> = (0..block_size - 1).map(|_| 0).collect();

    loop {
        let mut output_to_char: HashMap<String, u8> = HashMap::new();
        for i in 0..128 {
            let mut combined = padding.clone();
            combined.append(&mut deciphered.clone());
            combined.push(i);
            let relevant_output = &oracle(&combined, &unknown_key)[0..combined.len()].to_vec();
            output_to_char
                .entry(bytes_to_hex_string(relevant_output))
                .or_insert(i);
        }
        let oracle_output = oracle(&padding, &unknown_key);
        let next = match output_to_char.get(&bytes_to_hex_string(
            &oracle_output[0..=padding.len() + deciphered.len()],
        )) {
            Some(c) => c,
            None => return Ok(()),
        };
        if padding.is_empty() {
            /*
             * When we reach the end of the block we need to start using the
             * next available block for the attack. For instance, decoding the
             * alphabet encrypted under a 4-byte cypher might look like this:
             * XXX?????
             * XXA?????
             * XAB?????
             * ABC?????
             * XXXABCD?
             * Now instead of varying the character in the final block spot of
             * our first block, we vary the character in the final block spot
             * of our second block. This goes on until you've decrypted the
             * whole message.
             */
            padding = (0..block_size - 1).map(|_| 0).collect();
        } else {
            padding.pop();
        }
        deciphered.push(*next);
        print!("{}", *next as char);
        io::stdout().flush().unwrap();
    }
}
