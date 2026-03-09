// pe_structures.rs
// PE format structures for x86 and x64

#![allow(non_snake_case, dead_code)]

use std::fmt;

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct IMAGE_DOS_HEADER {

}

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct IMAGE_FILE_HEADER {

}

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct IMAGE_DATA_DIRECTORY {

}

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct IMAGE_OPTIONAL_HEADER32 {

}

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct IMAGE_OPTIONAL_HEADER64 {

}

// Section header

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct IMAGE_SECTION_HEADER {
    pub name: [u8; 8],
}

impl IMAGE_SECTION_HEADER {
    pub fn name_str(&self) -> String {
        let nul = self.name.iter().position(|&b| b == 0).unwrap_or(8);
        String::from_utf8_lossy(&self.name[..nul]).to_string()
    }
}

impl fmt::Display for IMAGE_SECTION_HEADER {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name_str())
    }
}

// Base relocation
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct IMAGE_BASE_RELOCATION {
    pub virtual_address: u32,
    pub size_of_block: u32,
}

// Import descriptor
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct IMAGE_IMPORT_DESCRIPTOR {

}

// Helper
