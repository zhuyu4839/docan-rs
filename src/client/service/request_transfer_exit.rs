//! response of Service 37

use crate::{client::DoCanClient, DoCanResult};
use iso14229_1::Service;
use iso15765_2::can::AddressType;
use rs_can::{CanDevice, CanFrame};
use std::{fmt::Display, hash::Hash};

impl<D, C, F> DoCanClient<D, C, F>
where
    D: CanDevice<Channel = C, Frame = F> + Clone + Send + 'static,
    C: Clone + Eq + Display + Hash + Send + Sync + 'static,
    F: CanFrame<Channel = C> + Clone + Display + 'static,
{
    pub(crate) async fn _request_transfer_exit(&self, parameter: Vec<u8>) -> DoCanResult<Vec<u8>> {
        let cfg = self.context.get_cfg().await;
        let request = Self::make_request(Service::RequestTransferExit, None, parameter, &cfg)?;

        let response = self
            .send_and_response(AddressType::Physical, request, None, &cfg)
            .await?;

        Ok(response.raw_data().to_vec())
    }
}
