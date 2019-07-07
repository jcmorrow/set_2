extern crate challenge_10;
use challenge_10::*;

fn main() {
    let padded = "ICE ICE BABY\x04\x04\x04\x04";
    println!(
        "{}",
        bytes_to_string(&valid_pkcs_7_padding(&padded.as_bytes()).unwrap())
    );
}

pub fn valid_pkcs_7_padding(input: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut destructable = input.to_vec();
    let padding_len = match destructable.pop() {
        Some(0) => return Result::Err("Invalid padding"),
        None => return Result::Err("No content"),
        Some(x) => x,
    };
    let mut found = 1;
    while found < padding_len {
        match destructable.pop() {
            Some(padding) => {
                if padding_len == padding {
                    found += 1;
                } else {
                    return Result::Err("Invalid padding");
                }
            }
            None => return Result::Err("Invalid padding"),
        }
    }
    Result::Ok(destructable)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_valid_pkcs_7_padding() {
        let input1 = "ICE ICE BABY\x04\x04\x04\x04";
        let input2 = "ICE ICE BABY\x06\x06\x06\x06\x06\x06";

        assert_eq!(
            valid_pkcs_7_padding(&input1.as_bytes()).unwrap(),
            b"ICE ICE BABY",
        );
        assert_eq!(
            valid_pkcs_7_padding(&input2.as_bytes()).unwrap(),
            b"ICE ICE BABY",
        );
    }

    #[test]
    fn test_invalid_pkcs_7_padding() {
        let input1 = "ICE ICE BABY\x05\x05\x05\x05";
        let input2 = "ICE ICE BABY\x01\x02\x03\x04";
        assert!(valid_pkcs_7_padding(&input1.as_bytes()).is_err(),);
        assert!(valid_pkcs_7_padding(&input2.as_bytes()).is_err(),);
    }
}
