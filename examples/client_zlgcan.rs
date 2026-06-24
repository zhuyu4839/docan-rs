use docan_rs::DoCanClient;
use iso14229_1::{DataIdentifier, SessionType};
use iso15765_2::{
    can::{Address, AddressType},
    IsoTp as _,
};
use rs_can::{CanDevice, ChannelConfig, DeviceBuilder};
use rsutil::types::ByteOrder;
use std::sync::Arc;
use tokio_stream::StreamExt as _;
use uds_trait::{UdsClient, UdsLayer as _};
use zlgcan_rs::{
    can::{ZCanChlMode, ZCanChlType, ZCanFrame},
    device::ZCanDeviceType,
    driver::ZDriver,
    CHANNEL_MODE, CHANNEL_TYPE, DEVICE_INDEX, DEVICE_TYPE, LIBPATH,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let device = init_driver().await?;
    let mut client = init_client(device.clone()).await?;
    let mut src_tp_layer = client.tp_layer();
    src_tp_layer.start(100).await;

    let tp_layer = src_tp_layer.clone();
    let handle = tokio::task::spawn(async move {
        let mut stream = tp_layer.frame_stream().await.unwrap();
        while let Some(frame) = stream.next().await {
            println!("{}", frame)
        }
    });
    let handle = Arc::new(handle);

    let mut device = device.clone();
    let mut tp_layer = src_tp_layer.clone();
    let _guard = scopeguard::guard((), |_| {
        futures::executor::block_on(async {
            tp_layer.stop().await;
            device.shutdown();
            handle.abort();
        });
    });

    client
        .session_ctrl(SessionType::Extended, false, AddressType::Functional)
        .await?;
    let did = client
        .read_data_by_identifier(DataIdentifier::VIN, vec![])
        .await?;
    let data = did.data;
    println!("{:?}", String::from_utf8(data.data));

    Ok(())
}

async fn init_driver() -> anyhow::Result<ZDriver> {
    let mut builder = DeviceBuilder::new();

    let mut chl_cfg = ChannelConfig::new(500_000);
    chl_cfg
        .add_other(CHANNEL_MODE, Box::new(ZCanChlMode::Normal))
        .add_other(CHANNEL_TYPE, Box::new(ZCanChlType::CAN));

    builder
        .add_other(LIBPATH, Box::new("rust-can/library".to_string()))
        .add_other(DEVICE_TYPE, Box::new(ZCanDeviceType::ZCAN_USBCANFD_200U))
        .add_other(DEVICE_INDEX, Box::new(0u32))
        .add_config(0, chl_cfg);

    let device = builder.build::<ZDriver>()?;

    Ok(device)
}

async fn init_client(device: ZDriver) -> anyhow::Result<DoCanClient<ZDriver, u8, ZCanFrame>> {
    let address = Address {
        tx_id: 0x7E2,
        rx_id: 0x7EA,
        fid: 0x7DF,
    };
    let client = DoCanClient::new(device, 0, address, ByteOrder::default(), Some(200)).await;
    client.add_data_identifier(DataIdentifier::VIN, 17).await;

    Ok(client)
}
