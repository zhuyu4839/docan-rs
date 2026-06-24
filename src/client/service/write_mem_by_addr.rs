//! response of Service 3D

use crate::{client::DoCanClient, DoCanError, DoCanResult};
use iso14229_1::{request, response, AddressAndLengthFormatIdentifier, Service};
use iso15765_2::can::AddressType;
use rs_can::{CanDevice, CanFrame};
use std::{fmt::Display, hash::Hash};

impl<D, C, F> DoCanClient<D, C, F>
where
    D: CanDevice<Channel = C, Frame = F> + Clone + Send + 'static,
    C: Clone + Eq + Display + Hash + Send + Sync + 'static,
    F: CanFrame<Channel = C> + Clone + Display + 'static,
{
    pub(crate) async fn _write_memory_by_address(
        &self,
        alfi: AddressAndLengthFormatIdentifier,
        mem_addr: u128,
        mem_size: u128,
        record: Vec<u8>,
    ) -> DoCanResult<response::WriteMemByAddr> {
        let data = request::WriteMemByAddr::new(alfi, mem_addr, mem_size, record)
            .map_err(DoCanError::Iso14229Error)?;
        let cfg = self.context.get_cfg().await;
        let request = Self::make_request(Service::WriteMemByAddr, None, data, &cfg)?;

        self.send_and_parse(AddressType::Physical, request, None, &cfg)
            .await
    }
}
