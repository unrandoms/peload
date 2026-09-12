//loader.rs
//PE loading logic for x86 and x64
//Author: iss4cf0ng/ISSAC (extended by peload fork)
//GitHub: https://github.com/unrandoms/peload

use std::ffi::CString;
use windows::{
    Win32::{
        Foundation::HANDLE,
        System::{
            LibraryLoader::{GetProcAddress, LoadLibraryA},
            Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAlloc},
            Threading::{CreateThread, INFINITE, WaitForSingleObject},
        },
    },
    core::PCSTR,
};

#[allow(unused_imports)]
use crate::logger::{log_error, log_info, log_ok};
use crate::pe_structures::*;
use crate::error::LoadError;

//x86 PE loader

#[allow(dead_code)]
pub struct X86PeLoader {
    pub raw_bytes: Vec<u8>, //file bytes
    pub dos_header: IMAGE_DOS_HEADER,
    pub file_header: IMAGE_FILE_HEADER,
    pub optional_header: IMAGE_OPTIONAL_HEADER32,
    pub sections: Vec<IMAGE_SECTION_HEADER>,
}

impl X86PeLoader {
    pub fn new(bytes: Vec<u8>) -> Result<Self, LoadError> {
        unsafe {
            let data = bytes.as_ptr();
            let dos: IMAGE_DOS_HEADER = read_struct(data, 0);
            if dos.e_magic != 0x5A4D {
                return Err(LoadError::InvalidPeHeader("invalid DOS signature (not MZ)".to_string()));
            }

            let nt_offset = dos.e_lfanew as usize;
            let file_hdr: IMAGE_FILE_HEADER = read_struct(data, nt_offset + 4);
            let opt_hdr: IMAGE_OPTIONAL_HEADER32 = read_struct(data, nt_offset + 4 + std::mem::size_of::<IMAGE_FILE_HEADER>());
            let sections_offset = nt_offset + 4 + std::mem::size_of::<IMAGE_FILE_HEADER>() + std::mem::size_of::<IMAGE_OPTIONAL_HEADER32>();

            let mut sections = Vec::new();
            for i in 0..file_hdr.number_of_sections as usize {
                let sec: IMAGE_SECTION_HEADER = read_struct(data, sections_offset + i * std::mem::size_of::<IMAGE_SECTION_HEADER>());
                sections.push(sec);
            }

            Ok(Self {
                raw_bytes: bytes,
                dos_header: dos,
                file_header: file_hdr,
                optional_header: opt_hdr,
                sections,
            })
        }
    }

    pub fn is_32bit(&self) -> bool {
        self.optional_header.magic == 0x010B //PE32
    }
}

pub fn load_x86(pe: &X86PeLoader) -> Result<(), LoadError> {
    unsafe {
        //Memory allocation
        let opt = &pe.optional_header;
        let image_base = VirtualAlloc(
            None,
            opt.size_of_image as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );

        if image_base.is_null() {
            return Err(LoadError::AllocationFailed("VirtualAlloc() failed for image".to_string()));
        }

        let size_of_image = opt.size_of_image;
        log_ok(&format!("Alloced {:#X} bytes at {:#X}", size_of_image, image_base as usize));

        let base = image_base as *mut u8;
        let raw = pe.raw_bytes.as_ptr();

        //Copy headers
        std::ptr::copy_nonoverlapping(raw, base, opt.size_of_headers as usize);

        //Copy sections
        for sec in &pe.sections {
            let dest = base.add(sec.virtual_address as usize);
            std::ptr::copy_nonoverlapping(
                raw.add(sec.pointer_to_raw_data as usize),
                dest,
                sec.size_of_raw_data as usize,
            );
            log_info(&format!("Section {:>8} copied to {:#X}", sec.name_str(), dest as usize));
        }

        //Relocation
        let delta = image_base as i64 - opt.image_base as i64;
        if delta != 0 {
            let reloc_dir = &opt.base_relocation_table;
            if reloc_dir.size == 0 {
                return Err(LoadError::RelocationFailed("relocation table size is zero but delta is non-zero".to_string()));
            }

            let reloc_base = base.add(reloc_dir.virtual_address as usize);
            let mut offset: usize = 0;

            loop {
                let block: IMAGE_BASE_RELOCATION = read_struct(reloc_base, offset);
                if block.size_of_block == 0 {
                    break;
                }

                let count = ((block.size_of_block - 8) / 2) as usize;
                let fixup_base = base.add(block.virtual_address as usize);

                for i in 0..count {
                    let value = std::ptr::read_unaligned(
                        reloc_base.add(offset + 8 + i * 2) as *const u16,
                    );
                    let reloc_type = value >> 12;
                    let rva = (value & 0xFFF) as usize;

                    if reloc_type == 0x3 {
                        let patch = fixup_base.add(rva) as *mut i32;
                        let original = std::ptr::read_unaligned(patch);
                        std::ptr::write_unaligned(patch, original + delta as i32);
                    }
                }

                offset += block.size_of_block as usize;
            }
        }

        //Import libraries
        let import_dir = &opt.import_table;
        if import_dir.size == 0 {
            return Err(LoadError::IatResolutionFailed("import table size is zero".to_string()));
        }

        let desc_size = std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>();
        let mut desc_ptr = base.add(import_dir.virtual_address as usize) as *const IMAGE_IMPORT_DESCRIPTOR;

        loop {
            let desc: IMAGE_IMPORT_DESCRIPTOR = std::ptr::read_unaligned(desc_ptr);
            if desc.name == 0 {
                break;
            }

            let ptr_dll_name = base.add(desc.name as usize);
            let dll_name = read_ansi_string(ptr_dll_name);
            log_info(&format!("DLL: {}", dll_name));

            let dll_cstr = CString::new(dll_name.clone())
                .map_err(|e| LoadError::IatResolutionFailed(e.to_string()))?;
            let h_dll = LoadLibraryA(PCSTR(dll_cstr.as_ptr() as *const u8))
                .map_err(|e| LoadError::IatResolutionFailed(format!("LoadLibrary({}) failed: {}", dll_name, e)))?;

            let mut thunk_ref = base.add(if desc.original_first_thunk != 0 {
                desc.original_first_thunk as usize
            } else {
                desc.first_thunk as usize
            }) as *const u32;

            let mut func_ref = base.add(desc.first_thunk as usize) as *mut u32;
            loop {
                let thunk_data = std::ptr::read_unaligned(thunk_ref);
                if thunk_data == 0 {
                    break;
                }

                let func_addr = if (thunk_data & 0x80000000) != 0 {
                    //Import by ordinal
                    let ordinal = (thunk_data & 0xFFFF) as usize;
                    GetProcAddress(h_dll, PCSTR(ordinal as *const u8))
                } else {
                    //Import by name
                    let p_name = base.add(thunk_data as usize + 2);
                    let func_name = read_ansi_string(p_name);
                    let func_cstr = CString::new(func_name)
                        .map_err(|e| LoadError::IatResolutionFailed(e.to_string()))?;
                    GetProcAddress(h_dll, PCSTR(func_cstr.as_ptr() as *const u8))
                };

                if let Some(addr) = func_addr {
                    std::ptr::write_unaligned(func_ref, addr as usize as u32);
                }

                thunk_ref = thunk_ref.add(1);
                func_ref = func_ref.add(1);
            }

            desc_ptr = (desc_ptr as *const u8).add(desc_size) as *const IMAGE_IMPORT_DESCRIPTOR;
        }

        //TLS callbacks (invoked after relocation and IAT resolution, before entry point)
        invoke_tls_callbacks_x86(base, opt)?;

        //Go to OEP
        if opt.address_of_entry_point == 0 {
            return Err(LoadError::EntryPointInvalid);
        }
        log_ok("Jump to OEP");
        let entry = base.add(opt.address_of_entry_point as usize);
        let h_thread = CreateThread(
            None,
            0,
            Some(std::mem::transmute::<*const (), unsafe extern "system" fn(*mut std::ffi::c_void) -> u32>(entry as *const ())),
            None,
            Default::default(),
            None,
        )
        .map_err(|e| LoadError::WindowsApiError(format!("CreateThread failed: {}", e)))?;

        WaitForSingleObject(HANDLE(h_thread.0), INFINITE);
        Ok(())
    }
}

/// Walk the TLS directory for a 32-bit image and call each callback with DLL_PROCESS_ATTACH.
/// Skips gracefully when the TLS data directory is absent (virtual_address == 0).
unsafe fn invoke_tls_callbacks_x86(base: *mut u8, opt: &IMAGE_OPTIONAL_HEADER32) -> Result<(), LoadError> {
    let tls_va = opt.tls_table.virtual_address;
    if tls_va == 0 {
        return Ok(());
    }

    let tls: IMAGE_TLS_DIRECTORY32 = read_struct(base, tls_va as usize);
    let callbacks_va = tls.address_of_callbacks;
    if callbacks_va == 0 {
        return Ok(());
    }

    //address_of_callbacks is an absolute VA; convert to a pointer into the mapped image.
    //The image was loaded at `base` and the preferred base is opt.image_base.
    let delta = base as i64 - opt.image_base as i64;
    let cb_ptr = (callbacks_va as i64 + delta) as *const u32;

    let mut i = 0usize;
    loop {
        let cb_rva = std::ptr::read_unaligned(cb_ptr.add(i));
        if cb_rva == 0 {
            break;
        }
        let cb_va = (cb_rva as i64 + delta) as *const ();
        let callback: TlsCallback = std::mem::transmute(cb_va);
        log_info(&format!("Invoking TLS callback[{}] at {:#X}", i, cb_va as usize));
        callback(base as *mut std::ffi::c_void, DLL_PROCESS_ATTACH, std::ptr::null_mut());
        i += 1;
    }

    Ok(())
}

//x64 PE loader

#[allow(dead_code)]
pub struct X64PeLoader {
    pub raw_bytes: Vec<u8>,
    pub dos_header: IMAGE_DOS_HEADER,
    pub file_header: IMAGE_FILE_HEADER,
    pub optional_header32: IMAGE_OPTIONAL_HEADER32,
    pub optional_header64: IMAGE_OPTIONAL_HEADER64,
    pub sections: Vec<IMAGE_SECTION_HEADER>,
}

impl X64PeLoader {
    pub fn new(bytes: Vec<u8>) -> Result<Self, LoadError> {
        unsafe {
            let data = bytes.as_ptr();

            let dos: IMAGE_DOS_HEADER = read_struct(data, 0);
            if dos.e_magic != 0x5A4D {
                return Err(LoadError::InvalidPeHeader("invalid DOS signature (not MZ)".to_string()));
            }

            let nt_offset = dos.e_lfanew as usize;
            let file_hdr: IMAGE_FILE_HEADER = read_struct(data, nt_offset + 4);
            let opt_offset = nt_offset + 4 + std::mem::size_of::<IMAGE_FILE_HEADER>();
            let is_32bit = (file_hdr.characteristics & IMAGE_FILE_32BIT_MACHINE) != 0;

            let opt32: IMAGE_OPTIONAL_HEADER32 = if is_32bit {
                read_struct(data, opt_offset)
            } else {
                Default::default()
            };

            let opt64: IMAGE_OPTIONAL_HEADER64 = if !is_32bit {
                read_struct(data, opt_offset)
            } else {
                Default::default()
            };

            let sections_offset = opt_offset + if is_32bit {
                std::mem::size_of::<IMAGE_OPTIONAL_HEADER32>()
            } else {
                std::mem::size_of::<IMAGE_OPTIONAL_HEADER64>()
            };

            let mut sections = Vec::new();
            for i in 0..file_hdr.number_of_sections as usize {
                let sec: IMAGE_SECTION_HEADER = read_struct(
                    data,
                    sections_offset + i * std::mem::size_of::<IMAGE_SECTION_HEADER>(),
                );
                sections.push(sec);
            }

            Ok(Self {
                raw_bytes: bytes,
                dos_header: dos,
                file_header: file_hdr,
                optional_header32: opt32,
                optional_header64: opt64,
                sections,
            })
        }
    }

    pub fn is_32bit_header(&self) -> bool {
        (self.file_header.characteristics & IMAGE_FILE_32BIT_MACHINE) != 0
    }
}

pub fn load_x64(pe: &X64PeLoader) -> Result<(), LoadError> {
    unsafe {
        let opt = &pe.optional_header64;
        let raw = pe.raw_bytes.as_ptr();

        //Memory allocation
        let codebase = VirtualAlloc(
            None,
            opt.size_of_image as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );

        if codebase.is_null() {
            return Err(LoadError::AllocationFailed("VirtualAlloc() failed for image".to_string()));
        }

        let base = codebase as *mut u8;
        let size_of_image = opt.size_of_image;
        log_ok(&format!("Allocated {:#X} bytes at {:#X}", size_of_image, codebase as usize));

        //Copy sections
        log_info("Copying sections");
        for sec in &pe.sections {
            let dest = VirtualAlloc(
                Some(base.add(sec.virtual_address as usize) as *mut _),
                sec.size_of_raw_data as usize,
                MEM_COMMIT,
                PAGE_EXECUTE_READWRITE,
            );

            if dest.is_null() {
                return Err(LoadError::SectionMappingFailed(format!(
                    "VirtualAlloc failed for section {}",
                    sec.name_str()
                )));
            }

            std::ptr::copy_nonoverlapping(
                raw.add(sec.pointer_to_raw_data as usize),
                dest as *mut u8,
                sec.size_of_raw_data as usize,
            );

            log_info(&format!("Section {:>8} copied to {:#X}", sec.name_str(), dest as usize));
        }

        //Relocation
        let delta = codebase as i64 - opt.image_base as i64;
        log_ok(&format!("Delta = {:#X}", delta));

        let reloc_va = opt.base_relocation_table.virtual_address;
        let reloc_size = opt.base_relocation_table.size;
        log_info(&format!("Relocation table VA: {:#X}, size: {:#X}", reloc_va, reloc_size));

        let reloc_table = base.add(reloc_va as usize);
        let base_reloc_size = std::mem::size_of::<IMAGE_BASE_RELOCATION>();

        let mut current_offset: usize = 0;
        let total_reloc_size = reloc_size as usize;

        while current_offset < total_reloc_size {
            let block: IMAGE_BASE_RELOCATION = read_struct(reloc_table, current_offset);
            if block.size_of_block == 0 {
                break;
            }

            let entry_count = (block.size_of_block as usize - base_reloc_size) / 2;
            let dest = base.add(block.virtual_address as usize);

            log_info(&format!("Relocation block: {} entries", entry_count));

            for i in 0..entry_count {
                let value = std::ptr::read_unaligned(
                    reloc_table.add(current_offset + base_reloc_size + i * 2) as *const u16,
                );
                let reloc_type = value >> 12;
                let fixup = (value & 0xFFF) as usize;

                match reloc_type {
                    0x0 => {}
                    0xA => {
                        let patch = dest.add(fixup) as *mut i64;
                        let original = std::ptr::read_unaligned(patch);
                        std::ptr::write_unaligned(patch, original + delta);
                    }
                    _ => {}
                }
            }

            current_offset += block.size_of_block as usize;
        }

        //Import libraries
        let import_rva = opt.import_table.virtual_address as usize;
        let desc_size = std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>();
        let mut j = 0usize;

        loop {
            let desc: IMAGE_IMPORT_DESCRIPTOR = read_struct(base, import_rva + j * desc_size);

            if desc.name == 0 {
                break;
            }

            let dll_name = read_ansi_string(base.add(desc.name as usize));
            log_info(&format!("DLL: {}", dll_name));

            let dll_cstr = CString::new(dll_name.clone())
                .map_err(|e| LoadError::IatResolutionFailed(e.to_string()))?;
            let h_dll = LoadLibraryA(PCSTR(dll_cstr.as_ptr() as *const u8))
                .map_err(|e| LoadError::IatResolutionFailed(format!("LoadLibrary({}) failed: {}", dll_name, e)))?;

            let int_rva = if desc.original_first_thunk != 0 {
                desc.original_first_thunk as usize
            } else {
                desc.first_thunk as usize
            };
            let iat_rva = desc.first_thunk as usize;

            let mut k = 0usize;
            loop {
                let thunk = std::ptr::read_unaligned(base.add(int_rva + k * 8) as *const u64);
                if thunk == 0 {
                    break;
                }

                let func_addr = if (thunk & (1u64 << 63)) != 0 {
                    //Ordinal import
                    let ordinal = (thunk & 0xFFFF) as usize;
                    GetProcAddress(h_dll, PCSTR(ordinal as *const u8))
                } else {
                    //Name import
                    let name_ptr = base.add((thunk & 0x7FFF_FFFF_FFFF) as usize + 2);
                    let func_name = read_ansi_string(name_ptr);
                    let func_cstr = CString::new(func_name)
                        .map_err(|e| LoadError::IatResolutionFailed(e.to_string()))?;
                    GetProcAddress(h_dll, PCSTR(func_cstr.as_ptr() as *const u8))
                };

                if let Some(addr) = func_addr {
                    let iat_entry = base.add(iat_rva + k * 8) as *mut u64;
                    std::ptr::write_unaligned(iat_entry, addr as usize as u64);
                }

                k += 1;
            }

            j += 1;
        }

        //Register exception directory for x64 SEH/C++ exception unwinding
        #[cfg(target_arch = "x86_64")]
        register_exception_directory(base, opt)?;

        //TLS callbacks (invoked after relocation and IAT resolution, before entry point)
        invoke_tls_callbacks_x64(base, opt)?;

        //Go to OEP
        if opt.address_of_entry_point == 0 {
            return Err(LoadError::EntryPointInvalid);
        }
        log_ok("Jump to OEP");
        let entry = base.add(opt.address_of_entry_point as usize);

        let h_thread = CreateThread(
            None,
            0,
            Some(std::mem::transmute::<*const (), unsafe extern "system" fn(*mut std::ffi::c_void) -> u32>(entry as *const ())),
            None,
            Default::default(),
            None,
        )
        .map_err(|e| LoadError::WindowsApiError(format!("CreateThread failed: {}", e)))?;

        WaitForSingleObject(HANDLE(h_thread.0), INFINITE);
        Ok(())
    }
}

/// Register the exception directory (IMAGE_DIRECTORY_ENTRY_EXCEPTION) with the OS runtime.
/// Required on x64 so that SEH and C++ exceptions in the loaded PE can unwind correctly.
/// Without this call, any exception thrown inside the mapped image crashes the process
/// because RtlLookupFunctionEntry cannot find the UNWIND_INFO for frames inside the image.
/// Compiled only for x86_64; omitted entirely on x86 where frame-based unwinding is used.
#[cfg(target_arch = "x86_64")]
unsafe fn register_exception_directory(
    base: *mut u8,
    opt: &IMAGE_OPTIONAL_HEADER64,
) -> Result<(), LoadError> {
    use windows::Win32::System::Diagnostics::Debug::RtlAddFunctionTable;

    let exc_va = opt.exception_table.virtual_address;
    let exc_size = opt.exception_table.size;

    if exc_va == 0 || exc_size == 0 {
        log_info("No exception directory; skipping RtlAddFunctionTable");
        return Ok(());
    }

    //windows-rs IMAGE_RUNTIME_FUNCTION_ENTRY is the same layout as our struct:
    //BeginAddress: u32, EndAddress: u32, UnwindInfoAddress: u32 (in anonymous union)
    let entry_size = std::mem::size_of::<windows::Win32::System::Diagnostics::Debug::IMAGE_RUNTIME_FUNCTION_ENTRY>();
    let entry_count = exc_size as usize / entry_size;
    let pfunction_table = base.add(exc_va as usize)
        as *const windows::Win32::System::Diagnostics::Debug::IMAGE_RUNTIME_FUNCTION_ENTRY;

    log_info(&format!(
        "Registering {} RUNTIME_FUNCTION entries via RtlAddFunctionTable",
        entry_count
    ));

    //windows-rs 0.56 exposes: RtlAddFunctionTable(functiontable: &[IMAGE_RUNTIME_FUNCTION_ENTRY], baseaddress: u64)
    let runtime_funcs = std::slice::from_raw_parts(pfunction_table, entry_count);
    let result = RtlAddFunctionTable(runtime_funcs, base as u64);

    if result.as_bool() {
        log_ok("RtlAddFunctionTable succeeded");
        Ok(())
    } else {
        Err(LoadError::WindowsApiError(
            "RtlAddFunctionTable returned FALSE; SEH unwind table not registered".to_string(),
        ))
    }
}

/// Walk the TLS directory for a 64-bit image and call each callback with DLL_PROCESS_ATTACH.
/// Skips gracefully when the TLS data directory is absent (virtual_address == 0).
unsafe fn invoke_tls_callbacks_x64(base: *mut u8, opt: &IMAGE_OPTIONAL_HEADER64) -> Result<(), LoadError> {
    let tls_va = opt.tls_table.virtual_address;
    if tls_va == 0 {
        return Ok(());
    }

    let tls: IMAGE_TLS_DIRECTORY64 = read_struct(base, tls_va as usize);
    let callbacks_va = tls.address_of_callbacks;
    if callbacks_va == 0 {
        return Ok(());
    }

    //address_of_callbacks is an absolute VA in the 64-bit address space.
    //Convert to a pointer into the mapped image using the load delta.
    let delta = base as i64 - opt.image_base as i64;
    let cb_ptr = (callbacks_va as i64 + delta) as *const u64;

    let mut i = 0usize;
    loop {
        let cb_abs = std::ptr::read_unaligned(cb_ptr.add(i));
        if cb_abs == 0 {
            break;
        }
        //cb_abs is an absolute VA; apply the same delta to get the mapped address.
        let cb_mapped = (cb_abs as i64 + delta) as *const ();
        let callback: TlsCallback = std::mem::transmute(cb_mapped);
        log_info(&format!("Invoking TLS callback[{}] at {:#X}", i, cb_mapped as usize));
        callback(base as *mut std::ffi::c_void, DLL_PROCESS_ATTACH, std::ptr::null_mut());
        i += 1;
    }

    Ok(())
}
