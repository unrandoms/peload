//main.rs

/*
Author:  ISSAC
Github:  https://github.com/iss4cf0ng/IronPE
Version: 1.0.0
 */

#![cfg_attr(windows, windows_subsystem = "console")]
#![allow(non_snake_case)]

mod loader;
mod logger;
mod pe_structures;

use loader::{X64PeLoader, X86PeLoader};
use logger::{log_error, log_info, log_ok};
use std::env;
use std::fs;

fn main() {

}