use aya::maps::perf::{AsyncPerfEventArray};
use aya::programs::KProbe;
use aya::{include_bytes_aligned, Bpf};
use bytes::BytesMut;

use chapter_2_hello_buffer_common::Data;
use log::info;

use std::ffi::CStr;

use tokio::{select, signal};
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/hello-buffer"
    ))?;
    
    let mut output = AsyncPerfEventArray::try_from(bpf.map_mut("output")?)?;

    let program: &mut KProbe = bpf.program_mut("hello").unwrap().try_into()?;
    program.load()?;
    program.attach("__arm64_sys_execve", 0)?;

    let token = CancellationToken::new();
    let cloned_token = token.clone();

    let mut buf = output.open(0, None)?;

    tokio::spawn(async move {
        let mut buffers = (0..10)
            .map(|_| BytesMut::with_capacity(1024))
            .collect::<Vec<_>>();

        loop {
            select! {
                _ = cloned_token.cancelled() => { break; }
                events = buf.read_events(&mut buffers) => {
                    let events = events.unwrap();
                    for i in 0..events.read {
                        let buf = &mut buffers[i];
                        let ptr = buf.as_ptr() as *const Data;

                        unsafe {
                            let data = ptr.read_unaligned();
                            info!("{} {} {:?} {:?}", 
                                data.pid, 
                                data.uid, 
                                CStr::from_ptr(data.command.as_ptr() as *const u8), 
                                CStr::from_ptr(data.message.as_ptr() as *const u8));
                        }
                    }
                }
            }
        }
    });

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    token.cancel();
    info!("Exiting...");

    Ok(())
}
