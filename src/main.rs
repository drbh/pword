#[macro_use]
extern crate clap;
extern crate chbs;
extern crate rpassword;

use argon2::{self, Config};
use chbs::{config::BasicConfig, prelude::*, probability::Probability};
use rpassword::read_password;

use std::io;

fn main() {
    let matches = clap_app!(myapp =>
        (version: "1.0")
        (author: "David H. <david.richard.holtz@gmail.com>")
        (about: "🔥 a deterministic password generator 🤘")
        (@subcommand new =>
            (about: "create new master phrase")
        )
        (@subcommand generate =>
            (about: "generate new password")
            // (@arg INPUT: +required "Sets the new password host")
        )
    )
    .get_matches();

    if let Some(_matches) = matches.subcommand_matches("new") {
        let phrase = create_new_phrase(3);
        println!("{}", phrase);
    }

    if let Some(_matches) = matches.subcommand_matches("generate") {
        println!("Type a password: ");
        let password = read_password().unwrap();
        println!("👍 thanks.\n");
        println!("Type a label for your password");
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .expect("error: unable to read user input");
        let my_input = input.as_bytes();
        let salt = password.as_bytes();
        let config = Config::default();
        let hash = argon2::hash_encoded(my_input, salt, &config).unwrap();
        let _does_matches = argon2::verify_encoded(&hash, my_input).unwrap();
        println!("\nYour password:");
        let ss: String = hash.chars().skip(40).take(20).collect();
        println!("{}", ss);
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
