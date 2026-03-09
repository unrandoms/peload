use windows::Win32::System::Memory::*;

fn main() {
    unsafe {
        let mem = VirtualAlloc(
            None,
            1000,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );

        println!("Allocated memory at: {:?}", mem);
    }
}