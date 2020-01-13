use argon2::{self, Config};
use chbs::{config::BasicConfig, prelude::*, probability::Probability};
use clap::clap_app;
use rpassword::read_password;
use std::io;
use std::process;

const DEFAULT_PHRASE_WORD_COUNT: usize = 3;
const DEFAULT_PASS_LEN: usize = 20;

fn main() {
    println!(
        "
                                  __
    ____ _      ______  _________/ /
   / __ \\ | /| / / __ \\/ ___/ __  / 
  / /_/ / |/ |/ / /_/ / /  / /_/ /  
 / .___/|__/|__/\\____/_/   \\__,_/   
/_/                                 

secure password generator - v 0.1.3
"
    );

    let matches = clap_app!(myapp =>
        (version: "0.1.3")
        (author: "David H. <david.richard.holtz@gmail.com>")
        (about: "🔥 a deterministic password generator 🤘")
        (@subcommand new =>
            (about: "create new master pass phrase")
            (@arg words: -w --words +takes_value "Pass the number of words you want the phrase to be")
        )
        (@subcommand generate =>
            (about: "generate new password")
            (@arg len: -l --len +takes_value "The length of the password you want")
        )
    )
    .get_matches();
    // flag if user does nothing
    let mut was_called = false;
    if let Some(matches) = matches.subcommand_matches("new") {
        was_called = true;

        let mut execute_count = DEFAULT_PHRASE_WORD_COUNT;
        if let Some(user_count_words) = matches.value_of("words") {
            execute_count = String::from(user_count_words)
                .parse()
                .unwrap_or(execute_count);
            println!(
                "User entered count of {} words will be used:",
                execute_count
            );
        }
        let phrase = create_new_phrase(execute_count);
        println!("\nPhrase \"{}\" \n", phrase);
    }
    if let Some(matches) = matches.subcommand_matches("generate") {
        was_called = true;
        println!("Type your pass phrase: ");
        let password = read_password().expect("You did not enter a password!");

        if password.len() < 7 {
            println!("{}", "please use a longer pass phrase");
            process::exit(1);
        }

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
                let mut pass_execute_count = DEFAULT_PASS_LEN;
                if let Some(user_pass_len) = matches.value_of("len") {
                    pass_execute_count = String::from(user_pass_len)
                        .parse()
                        .unwrap_or(pass_execute_count);
                    println!(
                        "User entered password length of {} digits will be used:",
                        pass_execute_count
                    );
                }
                println!("\nYour password:");
                let ss: String = hash.chars().skip(40).take(pass_execute_count).collect();
                println!("{}", ss)
            }
            Err(e) => println!("{:?} please use a longer pass phrase", e), // prob never get here
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
