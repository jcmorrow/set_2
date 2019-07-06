/*
Implement PKCS#7 padding

A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of plaintext into ciphertext.
But we almost never want to transform a single block; we encrypt irregularly-sized messages.

One way we account for irregularly-sized messages is by padding, creating a plaintext that is an
even multiple of the blocksize. The most popular padding scheme is called PKCS#7.

So: pad any block to a specific block length, by appending the number of bytes of padding to the
end of the block. For instance,

"YELLOW SUBMARINE"

... padded to 20 bytes would be:

"YELLOW SUBMARINE\x04\x04\x04\x04"
*/

fn main() {
    let unpadded = "YELLOW SUBMARINE";
    let padded = pad(unpadded, 20);
    println!("{}", padded);
}

fn pad(s: &str, len: u32) -> String {
    let mut padded = String::from(s);
    while padded.as_bytes().len() < len as usize {
        padded.push('\x04');
    }
    padded
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_pad() {
        let a = "YELLOW SUBMARINE";

        assert_eq!(
            pad(a, 20).as_bytes(),
            &[89, 69, 76, 76, 79, 87, 32, 83, 85, 66, 77, 65, 82, 73, 78, 69, 4, 4, 4, 4],
        );
    }
}
