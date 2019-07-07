extern crate openssl;

use openssl::symm::{encrypt, Cipher, Crypter, Mode};

use std::io::Read;

const BASE_64_ALPHABET: [char; 64] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
    'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '+', '/',
];

pub fn decrypt_one_block_aes_128_ecb(data: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();

    let mut decrypted = Crypter::new(cipher, Mode::Decrypt, key, None).unwrap();
    let mut output = vec![0 as u8; data.len() + Cipher::aes_128_cbc().block_size()];

    let decrypted_result = decrypted.update(&data, &mut output);

    match decrypted_result {
        Ok(_) => output[0..16].to_owned(),
        Err(e) => panic!("Error decrypting text: {}", e),
    }
}

pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes().chunks(2).map(hex_to_byte).collect()
}

pub fn binary_to_byte(bs: &[u8]) -> u8 {
    let mut n: u8 = 0;

    for (i, b) in bs.iter().rev().enumerate() {
        n += (2 as u8).pow(i as u32) * b;
    }

    n
}

pub fn byte_to_binary(c: u8, bits: usize) -> Vec<u8> {
    let mut xs: Vec<u8> = Vec::new();
    let mut quotient: u8 = c as u8;
    let mut remainder: u8;

    while quotient > 0 {
        remainder = quotient % 2;
        quotient /= 2;
        xs.push(remainder);
    }

    xs = pad_with_null_bytes(&xs, bits);
    xs.reverse();
    xs
}

pub fn pad_with_null_bytes(xs: &[u8], len: usize) -> Vec<u8> {
    let mut xs = xs.to_vec();
    while xs.len() < len {
        xs.push(0);
    }
    xs
}

fn pad_with_x04(s: &[u8], len: u32) -> Vec<u8> {
    let mut padded = s.to_vec();

    while padded.len() < len as usize {
        println!("PUSHING");
        padded.push(0x04);
    }
    padded
}

pub fn hex_to_base_64(s: &str) -> String {
    let mut b64 = String::new();
    let mut bins: Vec<u8> = Vec::new();

    for byte in hex_to_bytes(s) {
        bins.append(&mut byte_to_binary(byte, 8));
    }

    for c in bins.chunks(6) {
        b64.push(BASE_64_ALPHABET[binary_to_byte(c) as usize]);
    }

    b64
}

pub fn hex_to_byte(hex: &[u8]) -> u8 {
    if let Ok(base_16) = String::from_utf8(hex.to_vec()) {
        u32::from_str_radix(&base_16, 16).unwrap() as u8
    } else {
        panic!("Could not parse {:?} as base-16", hex);
    }
}

pub fn hex_to_string(hex: &str) -> String {
    String::from_utf8(hex_to_bytes(hex))
        .expect("Non UTF-8 byte encounted while converting hex to UTF-8")
}

pub fn bytes_to_hex_string(xs: &[u8]) -> String {
    xs.iter().map(|x| byte_to_hex(*x)).collect()
}

pub fn byte_to_hex(b: u8) -> String {
    format!("{:0>2x}", b)
}

pub fn bytes_to_string(s: &[u8]) -> String {
    String::from_utf8(s.to_owned())
        .unwrap_or_else(|_| panic!("Can't turn {:?} into valid string", s))
}

pub fn base_64_to_hex(s: &str) -> String {
    let mut hex = String::new();
    let mut bins: Vec<u8> = Vec::new();

    for c in s.as_bytes() {
        let index = base_64_index(*c as char);
        if index > -1 {
            bins.append(&mut byte_to_binary(index as u8, 6));
        }
    }

    for c in bins.chunks(8) {
        hex.push_str(&byte_to_hex(binary_to_byte(c)));
    }

    hex
}

pub fn base_64_index(c: char) -> isize {
    for (i, ch) in BASE_64_ALPHABET.iter().enumerate() {
        if *ch == c {
            return i as isize;
        }
    }
    -1
}

pub fn decrypt_aes_128_ecb(encrypted: &[u8], key: &str) -> Vec<u8> {
    let block_size = 16;
    let mut plain: Vec<u8> = Vec::new();

    let blocks: Vec<&[u8]> = encrypted.chunks(block_size).rev().collect();
    for block in blocks {
        let decrypted_block = decrypt_one_block_aes_128_ecb(&block, key.as_bytes());
        plain.splice(0..0, decrypted_block.iter().cloned());
    }
    plain
}

pub fn encrypt_one_block_aes_128_ecb(decrypted: &[u8], key: &str) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();

    encrypt(cipher, key.as_bytes(), None, decrypted).unwrap()[0..16].to_owned()
}

pub fn encrypt_aes_128_ecb(decrypted: &[u8], key: &str) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();

    encrypt(cipher, key.as_bytes(), None, decrypted).unwrap()
}

pub fn encrypt_aes_128_cbc(plaintext: &[u8], key: &str) -> Vec<u8> {
    let block_size = 16;
    let blocks = plaintext.chunks(block_size);
    let mut encrypted: Vec<u8> = Vec::new();
    let mut previous_ciphertext_block: Vec<u8> = (0..block_size).map(|_| 0).collect();
    for block in blocks {
        let xored = &xor(
            &pad_with_x04(&block, block_size as u32),
            &previous_ciphertext_block,
        );
        let mut text = [0; 16];
        encrypt_aes_128_ecb(xored, key)
            .take(block_size as u64)
            .read_exact(&mut text)
            .unwrap();
        previous_ciphertext_block = text.to_vec();
        encrypted.append(&mut text.to_vec());
    }
    encrypted
}

pub fn decrypt_aes_128_cbc(encrypted: &[u8], key: &str) -> Vec<u8> {
    let block_size = 16;
    let mut plain: Vec<u8> = Vec::new();

    let blocks: Vec<&[u8]> = encrypted.chunks(block_size).rev().collect();
    for (i, block) in blocks.clone().iter().enumerate() {
        let previous_cyphertext = match blocks.get(i + 1) {
            Some(x) => x,
            None => &[0 as u8; 16][..],
        };
        let decrypted_block = decrypt_one_block_aes_128_ecb(&block, key.as_bytes());
        let plain_block = xor(&decrypted_block, previous_cyphertext);
        plain.splice(0..0, plain_block.iter().cloned());
    }
    plain
}

pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|x| x.0 ^ x.1).collect()
}

#[cfg(test)]
mod test {
    use super::*;
    use std::fs::File;
    use std::io::{BufReader, Read};

    #[test]
    fn test_decrypt_aes_ecb() {
        let file = File::open("7.txt").unwrap();
        let mut buf_reader = BufReader::new(file);
        let mut encrypted_base_64 = String::new();

        let decrypted_file = File::open("7_decrypted.txt").unwrap();
        let mut decrypted_buf_reader = BufReader::new(decrypted_file);
        let mut decrypted = String::new();
        decrypted_buf_reader.read_to_string(&mut decrypted).unwrap();

        buf_reader.read_to_string(&mut encrypted_base_64).unwrap();
        let encrypted = base_64_to_hex(&encrypted_base_64);
        let key = "YELLOW SUBMARINE";

        let round_tripped = decrypt_aes_128_ecb(&hex_to_bytes(&encrypted), key);
        assert_eq!(
            bytes_to_string(&pad_with_x04(
                &decrypted.as_bytes(),
                round_tripped.len() as u32
            )),
            bytes_to_string(&round_tripped)
        );
    }

    #[test]
    fn test_encrypt_aes_ecb() {
        let file = File::open("7.txt").unwrap();
        let mut buf_reader = BufReader::new(file);
        let mut encrypted_base_64 = String::new();

        let decrypted_file = File::open("7_decrypted.txt").unwrap();
        let mut decrypted_buf_reader = BufReader::new(decrypted_file);
        let mut decrypted = String::new();
        decrypted_buf_reader.read_to_string(&mut decrypted).unwrap();

        buf_reader.read_to_string(&mut encrypted_base_64).unwrap();
        let encrypted = base_64_to_hex(&encrypted_base_64);
        let key = "YELLOW SUBMARINE";

        assert_eq!(
            bytes_to_hex_string(&encrypt_aes_128_ecb(decrypted.as_bytes(), key)),
            encrypted,
        );
    }

    #[test]
    fn test_encrypt_aes_cbc() {
        let cbc_encrypted = File::open("10.txt").unwrap();
        let mut buf_reader = BufReader::new(cbc_encrypted);
        let mut cbc_encrypted_base_64 = String::new();
        buf_reader
            .read_to_string(&mut cbc_encrypted_base_64)
            .unwrap();
        let cbc_encrypted = hex_to_bytes(&base_64_to_hex(&cbc_encrypted_base_64));

        let decrypted_file = File::open("7_decrypted.txt").unwrap();
        let mut decrypted_buf_reader = BufReader::new(decrypted_file);
        let mut decrypted = String::new();
        decrypted_buf_reader.read_to_string(&mut decrypted).unwrap();

        let key = "YELLOW SUBMARINE";

        let encrypted = encrypt_aes_128_cbc(decrypted.as_bytes(), key);

        assert_eq!(
            bytes_to_hex_string(&cbc_encrypted),
            bytes_to_hex_string(&encrypted)
        );

        let candidate_decrypted = decrypt_aes_128_cbc(&encrypted, key);

        assert_eq!(
            bytes_to_hex_string(&candidate_decrypted),
            bytes_to_hex_string(&pad_with_x04(
                decrypted.as_bytes(),
                candidate_decrypted.len() as u32
            ))
        );
    }

}
