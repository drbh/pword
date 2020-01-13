use argon2::{self, Config};
use chbs::{config::BasicConfig, prelude::*, probability::Probability};
use clap::clap_app;
use rpassword::read_password;
use std::io;

fn main() {
    let matches = clap_app!(myapp =>
        (version: "1.0")
        (author: "David H. <david.richard.holtz@gmail.com>")
        (about: "🔥 a deterministic password generator 🤘")
        (@subcommand new =>
            (about: "create new master pass phrase")
        )
        (@subcommand generate =>
            (about: "generate new password")
        )
    )
    .get_matches();
    // flag if user does nothing
    let mut was_called = false;
    if let Some(_matches) = matches.subcommand_matches("new") {
        was_called = true;
        let phrase = create_new_phrase(3);
        println!("{}", phrase);
    }
    if let Some(_matches) = matches.subcommand_matches("generate") {
        was_called = true;
        println!("Type your pass phrase: ");
        let password = read_password().expect("You did not enter a password!");
        println!("👍 thanks.\n");
        println!("Type a label for your password");
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .expect("error: unable to read user input");
        let my_input = input.as_bytes();
        let salt = password.as_bytes();
        let config = Config::default();
        match argon2::hash_encoded(my_input, salt, &config) {
            Ok(hash) => {
                println!("\nYour password:");
                let ss: String = hash.chars().skip(40).take(20).collect();
                println!("{}", ss)
            }
            Err(e) => println!("{:?} please use a longer pass phrase", e),
        };
    }
    if was_called == false {
        println!("You did not specify [new] or [generate] type --help for more infomation");
    }
}

fn create_new_phrase(word_count: usize) -> String {
    let mut config = BasicConfig::default();
    config.words = word_count;
    config.separator = " ".into();
    config.capitalize_first = Probability::from(0.33);
    let mut scheme = config.to_scheme();
    scheme.generate()
}
