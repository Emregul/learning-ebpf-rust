#![no_std]
#![no_main]

use aya_bpf::{macros::{kprobe, map}, programs::ProbeContext, maps::PerfEventArray, cty::c_long, BpfContext};
// use aya_bpf::helpers::{bpf_get_current_uid_gid, bpf_get_current_pid_tgid, bpf_get_current_comm};

use chapter_2_hello_buffer_common::Data;

#[map(name = "output")]
static mut OUTPUT: PerfEventArray<Data> = PerfEventArray::with_max_entries(1024, 0);

#[kprobe(name = "hello")]
pub fn hello(ctx: ProbeContext) -> u32 {
    match try_hello(ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_hello(ctx: ProbeContext) -> Result<u32, c_long> {
    let pid = ctx.pid();
    // let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid = ctx.uid();
    // let uid = (bpf_get_current_uid_gid() & 0xFFFFFFFF) as u32;
    let command = ctx.command()?;

    let mut buff: [u8; 12] = [0;12];
    let message = "Hello World".as_bytes();
    buff[..message.len()].copy_from_slice(message);

    let data = Data {
        pid,
        uid,
        command,
        message: buff
    };

    unsafe { OUTPUT.output(&ctx, &data, 0) };

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}