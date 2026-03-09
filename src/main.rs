use std::env;
use std::fs;
use std::str;
use windows::Win32::System::Memory::*;

#[repr(C)]
struct IMAGE_DOS_HEADER {
    e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: [u16; 4],
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: [u16; 10],
    e_lfanew: i32,
}

#[repr(C)]
struct IMAGE_FILE_HEADER {
    Machine: u16,
    NumberOfSections: u16,
    TimeDateStamp: u32,
    PointerToSymbolTable: u32,
    NumberOfSymbols: u32,
    SizeOfOptionalHeader: u16,
    Characteristics: u16,
}

#[repr(C)]
struct IMAGE_OPTIONAL_HEADER64 {
    Magic: u16,
    MajorLinkerVersion: u8,
    MinorLinkerVersion: u8,
    SizeOfCode: u32,
    SizeOfInitializedData: u32,
    SizeOfUninitializedData: u32,
    AddressOfEntryPoint: u32,
    BaseOfCode: u32,
    ImageBase: u64,
}

#[repr(C)]
struct IMAGE_NT_HEADERS64 {
    Signature: u32,
    FileHeader: IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}

#[allow(dead_code)]
#[repr(C)]
struct IMAGE_SECTION_HEADER {
    Name: [u8; 8],
    VirtualSize: u32,
    VirtualAddress: u32,
    SizeOfRawData: u32,
    PointerToRawData: u32,
    PointerToRelocations: u32,
    PointerToLinenumbers: u32,
    NumberOfRelocations: u16,
    NumberOfLinenumbers: u16,
    Characteristics: u32,
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("Usage: IronPE <exe>");
        return;
    }

    let path = &args[1];
    let pe_bytes = fs::read(path).expect("Failed to read file.");
    println!("Loaded file: {}", path);
    println!("File size: {} bytes", pe_bytes.len());

    let dos_header = unsafe { &*(pe_bytes.as_ptr() as *const IMAGE_DOS_HEADER) };
    println!("DOS Magic: {:X}", dos_header.e_magic);
    println!("NT Header offset: {:X}", dos_header.e_lfanew);

    let nt_header = unsafe {
        &*(pe_bytes.as_ptr().add(dos_header.e_lfanew as usize) as *const IMAGE_NT_HEADERS64)
    };
    println!("NT Signature: {:X}", nt_header.Signature);
    println!("Machine: {:X}", nt_header.FileHeader.Machine);
    println!("EntryPoint: {:X}", nt_header.OptionalHeader.AddressOfEntryPoint);
    println!("ImageBase: {:X}", nt_header.OptionalHeader.ImageBase);

    let num_sections = nt_header.FileHeader.NumberOfSections as usize;
    println!("Number of sections: {}", num_sections);

    let section_table_ptr = unsafe {
        pe_bytes.as_ptr().add(
            dos_header.e_lfanew as usize
                + std::mem::size_of::<u32>() //Signature
                + std::mem::size_of::<IMAGE_FILE_HEADER>()
                + nt_header.FileHeader.SizeOfOptionalHeader as usize,
        )
    };

    //Compute PE SizeOfImage
    let size_of_image = nt_header.OptionalHeader.SizeOfCode
        + nt_header.OptionalHeader.SizeOfInitializedData
        + nt_header.OptionalHeader.SizeOfUninitializedData;
    println!("Allocating memory: {} bytes", size_of_image);

    //VirtualAlloc()
    let mem = unsafe {
        VirtualAlloc(
            None,
            size_of_image as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };
    println!("Memory allocated at: {:p}", mem);

    //Copy headers
    unsafe {
        std::ptr::copy_nonoverlapping(pe_bytes.as_ptr(), mem as *mut u8, dos_header.e_lfanew as usize + std::mem::size_of::<IMAGE_NT_HEADERS64>());
    }
    println!("Copied PE headers.");

    //Copy sections
    for i in 0..num_sections {
        let section = unsafe {
            &*(section_table_ptr.add(i * std::mem::size_of::<IMAGE_SECTION_HEADER>()) 
                as *const IMAGE_SECTION_HEADER)
        };

        //section name
        let name = section.Name;
        let name_str = match name.iter().position(|&c| c == 0) {
            Some(pos) => str::from_utf8(&name[..pos]).unwrap_or("???"),
            None => str::from_utf8(&name).unwrap_or("???"),
        };

        let dest = unsafe { (mem as *mut u8).add(section.VirtualAddress as usize) };
        let src = &pe_bytes[section.PointerToRawData as usize..][..section.SizeOfRawData as usize];

        unsafe {
            std::ptr::copy_nonoverlapping(src.as_ptr(), dest, section.SizeOfRawData as usize);
        }

        println!("Copied section: {}", name_str);
    }

    println!("Manual mapping complete (headers + sections).");
}