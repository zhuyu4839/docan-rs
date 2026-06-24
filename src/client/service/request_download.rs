//! response of Service 34

use iso14229_1::{
    request, response, AddressAndLengthFormatIdentifier, DataFormatIdentifier, MemoryLocation,
    Service,
};
use iso15765_2::can::AddressType;
use rs_can::{CanDevice, CanFrame};
use std::{fmt::Display, hash::Hash};

use crate::{DoCanClient, DoCanError, DoCanResult};

impl<D, C, F> DoCanClient<D, C, F>
where
    D: CanDevice<Channel = C, Frame = F> + Clone + Send + 'static,
    C: Clone + Eq + Display + Hash + Send + Sync + 'static,
    F: CanFrame<Channel = C> + Clone + Display + 'static,
{
    pub(crate) async fn _request_download(
        &self,
        alfi: AddressAndLengthFormatIdentifier,
        mem_addr: u128,
        mem_size: u128,
        dfi: Option<DataFormatIdentifier>,
    ) -> DoCanResult<response::RequestDownload> {
        let data = request::RequestDownload {
            dfi: dfi.unwrap_or_default(),
            mem_loc: MemoryLocation::new(alfi, mem_addr, mem_size)
                .map_err(DoCanError::Iso14229Error)?,
        };
        let cfg = self.context.get_cfg().await;
        let request = Self::make_request(Service::RequestDownload, None, data, &cfg)?;

        self.send_and_parse(AddressType::Physical, request, None, &cfg)
            .await
    }
}
