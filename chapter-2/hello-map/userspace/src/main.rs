use aya::maps::HashMap;
use aya::programs::KProbe;
use aya::{include_bytes_aligned, Bpf};

use log::info;

use tokio::select;
use tokio::{signal, time::{sleep, Duration}};

use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/hello-map"
    ))?;
    
    let counter_table:HashMap<_, u32, u32> = HashMap::try_from(bpf.map_mut("counter_table")?)?;

    let program: &mut KProbe = bpf.program_mut("hello").unwrap().try_into()?;
    program.load()?;
    program.attach("__arm64_sys_execve", 0)?;

    let token = CancellationToken::new();
    let cloned_token = token.clone();

    tokio::spawn(async move {
        loop {
            select! {
                _ = cloned_token.cancelled() => { break; }
                _ = sleep(Duration::from_secs(2)) => {}
            }

            let mut s = String::new();
            for item in counter_table.iter() {
                let (uid, count) = item.unwrap();
                s.push_str(format!("ID {uid}: {count} \t").as_str());
            }

            info!("{s}");
        }
    });

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    token.cancel();
    info!("Exiting...");

    Ok(())
}
