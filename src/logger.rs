//logger.rs
//colored console logging helpers

use std::io::Write;

pub fn log_ok(msg: &str) {
    //Green [+]
    print!("\x1b[32m[+]\x1b[0m ");
    println!("{}", msg);
    std::io::stdout().flush().ok();
}

pub fn log_info(msg: &str) {
    //Blue [*]
    print!("\x1b[34m[*]\x1b[0m ");
    println!("{}", msg);
    std::io::stdout().flush().ok();
}

pub fn log_error(msg: &str) {
    //Red [-]
    eprint!("\x1b[31m[-]\x1b[0m ");
    eprintln!("{}", msg);
    std::io::stderr().flush().ok();
}