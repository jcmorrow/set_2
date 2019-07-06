use challenge_12::*;
use challenge_2::*;
use challenge_3::*;
use std::fs;

fn main() {
    // If we already knew the key size we could use this, but let's pretend we dont'
    let plaintext = "SIXTEEN BYTES YO";
    // Who needs to know the key ahead of time?
    let unknown_key = random_aes_key();

    let mut key_size = 2;
    loop {
        let mut padding: Vec<u8> = Vec::new();
        for _ in 0..key_size {
            padding.push('A' as u8);
        }
        let oracle_output = oracle(&padding, &unknown_key);

        let first_two_bytes = &oracle_output[0..2];

        println!("{:?}", oracle_output);

        if oracle_output
            .chunks(2)
            .enumerate()
            .skip(1)
            .any(|(key_size, bytes)| bytes == first_two_bytes)
        {
            key_size /= 2;
            break;
        } else {
            key_size += 2;
        }
    }
    println!("Found key size: {}", key_size);

    //     println!(
    //         "{:?}",
    //         bytes_to_hex_string(&oracle(plaintext.as_bytes(), &unknown_key))
    //     );
}
