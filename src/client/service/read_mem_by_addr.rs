//! response of Service 23

use crate::{client::DoCanClient, DoCanResult};
use iso14229_1::{request, MemoryLocation, Service};
use iso15765_2::can::AddressType;
use rs_can::{CanDevice, CanFrame};
use std::{fmt::Display, hash::Hash};

impl<D, C, F> DoCanClient<D, C, F>
where
    D: CanDevice<Channel = C, Frame = F> + Clone + Send + 'static,
    C: Clone + Eq + Display + Hash + Send + Sync + 'static,
    F: CanFrame<Channel = C> + Clone + Display + 'static,
{
    pub(crate) async fn _read_memory_by_address(
        &self,
        mem_loc: MemoryLocation,
    ) -> DoCanResult<Vec<u8>> {
        let data = request::ReadMemByAddr(mem_loc);
        let cfg = self.context.get_cfg().await;
        let request = Self::make_request(Service::ReadMemByAddr, None, data, &cfg)?;

        let response = self
            .send_and_response(AddressType::Physical, request, None, &cfg)
            .await?;

        Ok(response.raw_data().to_vec())
    }
}
