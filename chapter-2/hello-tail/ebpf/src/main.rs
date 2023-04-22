#![no_std]
#![no_main]

use aya_bpf::{macros::{map, raw_tracepoint}, programs::RawTracePointContext, maps::ProgramArray, cty::c_long, BpfContext, PtRegs, bindings::user_pt_regs};
use aya_log_ebpf::info;

#[map(name = "syscall")]
static mut SYSCALL: ProgramArray = ProgramArray::with_max_entries(300, 0);

#[raw_tracepoint(name = "hello")]
pub fn hello(ctx: RawTracePointContext) -> i32 {
    match try_hello(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_hello(ctx: RawTracePointContext) -> Result<i32, c_long> {
    unsafe {
        let regs = PtRegs::new(ctx.as_ptr() as *mut user_pt_regs);
        let op_code: u32 = regs.arg(1).unwrap_or(0);
        
        // info!(&ctx, "Another syscall {}", op_code);
        SYSCALL.tail_call(&ctx, op_code)?;
    }
}

#[raw_tracepoint(name = "hello_exec")]
pub fn hello_exec(ctx: RawTracePointContext) -> u32 {
    info!(&ctx, "Executing a program");
    0
}

#[raw_tracepoint(name = "hello_timer")]
pub fn hello_timer(ctx: RawTracePointContext) -> Result<u32, c_long> {
        let regs = PtRegs::new(ctx.as_ptr() as *mut user_pt_regs);
        let op_code: u32 = regs.arg(1).unwrap_or(0);

        match op_code {
            222 => info!(&ctx, "Creating a timer"),
            226 => info!(&ctx, "Deleting a timer"),
            _   => info!(&ctx, "Some other timer operation")
        }
    
    Ok(0)
}

#[raw_tracepoint(name = "ignore_opcode")]
pub fn ignore_opcode(_ctx: RawTracePointContext) -> u32 {
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
