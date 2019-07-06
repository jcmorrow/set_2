use std::collections::HashMap;

fn main() {
    println!("{}", profile_for("josh@jcmorrow.com"));
    println!("{}", profile_for("foo@bar.com"));
    println!("{:?}", parse_cookie(&profile_for("foo@bar.com")));
}

fn profile_for(email: &str) -> String {
    let stripped_email = String::from(email).replace("=", "").replace("&", "");
    let mut profile: HashMap<String, String> = HashMap::new();
    profile.insert(String::from("uid"), String::from("10"));
    profile.insert(String::from("role"), String::from("user"));
    profile.insert(String::from("email"), stripped_email);
    generate_cookie(profile)
}

fn generate_cookie(cookie: HashMap<String, String>) -> String {
    cookie
        .iter()
        .map(|(key, value)| {
            let mut s = String::new();
            s.push_str(&key);
            s.push('=');
            s.push_str(&value);
            s
        })
        .collect::<Vec<String>>()
        .join("&")
}

fn parse_cookie(cookie: &str) -> HashMap<String, String> {
    let mut parsed: HashMap<String, String> = HashMap::new();
    for key_val in String::from(cookie).split('&') {
        let mut split_by_equal = key_val.split('=').take(2).collect::<Vec<&str>>();
        let value = split_by_equal.pop().unwrap();
        let key = split_by_equal.pop().unwrap();
        parsed.insert(String::from(key), String::from(value));
    }
    parsed
}
