#![no_std]
#![no_main]

use aya_bpf::{macros::raw_tracepoint, programs::RawTracePointContext, PtRegs, BpfContext, bindings::user_pt_regs};
use aya_log_ebpf::info;

#[raw_tracepoint(name = "hello")]
pub fn hello(ctx: RawTracePointContext) -> u32 {
    let op_code = get_opcode(&ctx);
    info!(&ctx, "Syscall world {}",  op_code);
    0
}

#[inline(never)]
pub fn get_opcode(ctx: &RawTracePointContext) -> u32 {
    let regs = PtRegs::new(ctx.as_ptr() as *mut user_pt_regs);
    regs.arg(1).unwrap_or(0)
}


#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

