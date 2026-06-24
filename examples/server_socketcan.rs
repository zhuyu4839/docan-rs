use docan_rs::DoCanServer;
use rs_can::{CanDevice, DeviceBuilder};
use socketcan_rs::SocketCan;
use std::env;
use tokio::signal::ctrl_c;
use uds_trait::{UdsLayer as _, UdsServer as _};

fn security_algo(_: u8, seed: &[u8], salt: &[u8]) -> docan_rs::DoCanResult<Option<Vec<u8>>> {
    Ok(Some(
        seed.iter()
            .enumerate()
            .map(|(index, byte)| byte ^ salt[index % salt.len()])
            .collect(),
    ))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let iface = env::var("DOCAN_IFACE").unwrap_or("vcan0".to_string());
    let mut builder = DeviceBuilder::new();
    builder.add_config(iface.clone(), Default::default());

    let mut device = builder.build::<SocketCan>()?;
    let mut server = DoCanServer::new(device.clone(), iface.clone()).await?;
    server.update_security_algo(security_algo).await;

    server.service_forever(100).await;

    match ctrl_c().await {
        Ok(()) => {
            println!("\nCtrl+C Signal, exiting...");
        }
        Err(err) => {
            eprintln!("Ctrl+C error: {:?}", err);
        }
    }

    server.service_stop().await;
    device.shutdown();

    Ok(())
}
