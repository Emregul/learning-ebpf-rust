#![no_std]
#![no_main]

use aya_bpf::{macros::{kprobe, map}, programs::ProbeContext, maps::HashMap, cty::c_long, BpfContext};
// use aya_bpf::helpers::bpf_get_current_uid_gid;

#[map(name = "counter_table")]
static mut COUNTER_TABLE: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[kprobe(name = "hello")]
pub fn hello(ctx: ProbeContext) -> u32 {
    match try_hello(ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_hello(ctx: ProbeContext) -> Result<u32, c_long> {
    //
    // let uid = (bpf_get_current_uid_gid() & 0xFFFFFFFF) as u32;
    let uid = ctx.uid();

    unsafe {
        match COUNTER_TABLE.get_ptr_mut(&uid) {
            Some(x) => *x += 1,
            None => COUNTER_TABLE.insert(&uid, &0, 0)?
        }
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}