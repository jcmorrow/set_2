fn main() {
    println!("{}", make_comment("Hello, world!"));
}

fn make_comment(comment: &str) -> String {
    let mut result = String::from("comment1=cooking%20MCs;userdata=");
    result.push_str(comment);
    result.push_str(";comment2=%20like%20a%20pound%20of%20bacon");
    result
}
