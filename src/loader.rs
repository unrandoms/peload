// loader.rs
// PE loading logic for x86 and x64

use std::ffi::CString;
use windows::{
    core::PCSTR,
    Win32::{
        Foundation::HANDLE,
        System::{
            LibraryLoader::{GetProcAddress, LoadLibraryA},
            Memory::{VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE},
            Threading::{CreateThread, WaitForSingleObject, INFINITE},
        },
    },
};

#[allow(unused_imports)]
use crate::logger::{log_error, log_info, log_ok};
use crate::pe_structures::*;

pub struct X86PeLoader {
    
}

impl X86PeLoader {
    
}

pub struct X64PeLoader {
    
}

impl X64PeLoader {
    
}
