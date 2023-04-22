use aya::maps::ProgramArray;
use aya::programs::RawTracePoint;
use aya::{include_bytes_aligned, Bpf};

use aya_log::BpfLogger;
use log::{info, warn};

use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/hello-tail"
    ))?;
    
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    
    let mut syscall = ProgramArray::try_from(bpf.map_mut("syscall")?)?;

    let exec_fn: &mut RawTracePoint = bpf.program_mut("hello_exec").unwrap().try_into()?;
    exec_fn.load()?;
    syscall.set(59, exec_fn, 0)?;

    let timer_fn: &mut RawTracePoint = bpf.program_mut("hello_timer").unwrap().try_into()?;
    timer_fn.load()?;
    for op in [222, 223, 224, 225, 226] {
        syscall.set(op, &mut *timer_fn, 0)?;
    }

    let ignore_fn: &mut RawTracePoint = bpf.program_mut("ignore_opcode").unwrap().try_into()?;
    ignore_fn.load()?;
    for op in [21, 22, 25, 29, 56, 57, 63, 64, 66, 72, 73, 79, 98, 101, 115, 131, 134, 135, 139, 172, 233, 280, 291] {
        syscall.set(op, &mut *ignore_fn, 0)?;
    }
    
    let program: &mut RawTracePoint = bpf.program_mut("hello").unwrap().try_into()?;
    program.load()?;
    program.attach("sys_enter")?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
