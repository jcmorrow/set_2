fn main() {
    println!("Hello, world!");
}

pub fn valid_pkcs_7_padding(mut input: Vec<u8>) -> Result<Vec<u8>, &'static str> {
    let padding_len = match input.pop() {
        Some(0) => return Result::Err("Invalid padding"),
        None => return Result::Err("No content"),
        Some(x) => x,
    };
    let mut found = 1;
    while found < padding_len {
        match input.pop() {
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
    Result::Ok(input)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_valid_pkcs_7_padding() {
        let input1 = "ICE ICE BABY\x04\x04\x04\x04";
        let input2 = "ICE ICE BABY\x06\x06\x06\x06\x06\x06";

        assert_eq!(
            valid_pkcs_7_padding(input1.as_bytes().to_vec()).unwrap(),
            b"ICE ICE BABY",
        );
        assert_eq!(
            valid_pkcs_7_padding(input2.as_bytes().to_vec()).unwrap(),
            b"ICE ICE BABY",
        );
    }

    #[test]
    fn test_invalid_pkcs_7_padding() {
        let input1 = "ICE ICE BABY\x05\x05\x05\x05";
        let input2 = "ICE ICE BABY\x01\x02\x03\x04";
        assert!(valid_pkcs_7_padding(input1.as_bytes().to_vec()).is_err(),);
        assert!(valid_pkcs_7_padding(input2.as_bytes().to_vec()).is_err(),);
    }
}
