use aya::maps::HashMap;
use aya::maps::perf::AsyncPerfEventArray;
use aya::programs::KProbe;
use aya::{include_bytes_aligned, Bpf};
use bytes::BytesMut;

use log::info;
use chapter_4_hello_buffer_config_common::Data;

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
    let mut config: HashMap<_, u32, [u8; 12]> = HashMap::try_from(bpf.map_mut("config")?)?;

    let mut root_msg: [u8; 12] = [0;12];
    let message = b"Hey root!";
    root_msg[..message.len()].copy_from_slice(message);

    let mut user_msg: [u8; 12] = [0;12];
    let message = b"Hi user 501!";
    user_msg[..message.len()].copy_from_slice(message);

    config.insert(0, root_msg, 0)?;
    config.insert(501, user_msg, 0)?;

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