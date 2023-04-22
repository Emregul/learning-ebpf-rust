#![no_std]
#![no_main]

use aya_bpf::{macros::{kprobe, map}, programs::ProbeContext, maps::{PerfEventArray, HashMap}, cty::c_long, BpfContext};

use chapter_4_hello_buffer_config_common::Data;

#[map(name = "output")]
static mut OUTPUT: PerfEventArray<Data> = PerfEventArray::with_max_entries(1024, 0);

#[map(name = "config")]
static mut CONFIG: HashMap<u32, [u8; 12]> = HashMap::with_max_entries(1024, 0);

#[kprobe(name = "hello")]
pub fn hello(ctx: ProbeContext) -> u32 {
    match try_hello(ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_hello(ctx: ProbeContext) -> Result<u32, c_long> {
    let pid = ctx.pid();
    let uid = ctx.uid();
    let command = ctx.command()?;

    let mut buff: [u8; 12] = [0;12];
    let message = b"Hello World";
    buff[..message.len()].copy_from_slice(message);

    unsafe {
        let user_msg = CONFIG.get(&uid);

        if let Some(user_msg) = user_msg {
            buff = *user_msg;
        }
        
        let data = Data {
                pid,
                uid,
                command,
                message: buff
        };

        OUTPUT.output(&ctx, &data, 0);
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}