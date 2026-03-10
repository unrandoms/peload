//loader.rs
//PE loading logic for x86 and x64

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

//x86 PE loader

pub struct X86PeLoader {
    pub raw_bytes: Vec<u8>, //file bytes
    pub dos_header: IMAGE_DOS_HEADER,
    pub file_header: IMAGE_FILE_HEADER,
    pub optional_header: IMAGE_OPTIONAL_HEADER32,
    pub sections: Vec<IMAGE_SECTION_HEADER>,
}

impl X86PeLoader {
    pub fn new(bytes: Vec<u8>) -> Result<Self, String> {
        unsafe {
            let data = bytes.as_ptr();
            let dos: IMAGE_DOS_HEADER = read_struct(data, 0);
            
        }
    }
}

//x64 PE loader

pub struct X64PeLoader {
    
}

impl X64PeLoader {
    
}
