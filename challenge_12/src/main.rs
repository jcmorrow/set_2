use challenge_12::*;
use challenge_2::*;
use challenge_3::*;
use std::collections::HashMap;
use std::fs;

fn main() {
    // If we already knew the key size we could use this, but let's pretend we dont'
    let plaintext = "SIXTEEN BYTES YO";
    // Who needs to know the key ahead of time?
    let unknown_key = random_aes_key();

    let mut block_size = 4;
    let mut last_output: Vec<u8> = Vec::new();
    loop {
        let mut padding: Vec<u8> = Vec::new();
        for _ in 0..block_size {
            padding.push('A' as u8);
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
        println!("Confirmed ECB");
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
        let next = output_to_char
            [&bytes_to_hex_string(&oracle_output[0..=padding.len() + deciphered.len()])];
        if next == 0 {
            break;
        }
        if padding.is_empty() {
            padding = (0..block_size - 1).map(|_| 0).collect();
        } else {
            padding.pop();
        }
        deciphered.push(next);
        println!("{:?}", bytes_to_string(&deciphered));
    }
}
