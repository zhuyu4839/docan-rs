//! response of Service 36

use crate::{client::DoCanClient, DoCanError, DoCanResult};
use iso14229_1::{request, response, Service};
use iso15765_2::can::AddressType;
use rs_can::{CanDevice, CanFrame};
use std::{fmt::Display, hash::Hash};

impl<D, C, F> DoCanClient<D, C, F>
where
    D: CanDevice<Channel = C, Frame = F> + Clone + Send + 'static,
    C: Clone + Eq + Display + Hash + Send + Sync + 'static,
    F: CanFrame<Channel = C> + Clone + Display + 'static,
{
    pub(crate) async fn _transfer_data(
        &self,
        sequence: u8,
        data: Vec<u8>,
    ) -> DoCanResult<response::TransferData> {
        let data = request::TransferData { sequence, data };
        let cfg = self.context.get_cfg().await;
        let request = Self::make_request(Service::TransferData, None, data, &cfg)?;

        let response = self
            .send_and_response(AddressType::Physical, request, None, &cfg)
            .await?;

        let data = response
            .data::<response::TransferData>(&cfg)
            .map_err(DoCanError::Iso14229Error)?;

        if data.sequence != sequence {
            return Err(DoCanError::UnexpectedTransferSequence {
                expect: sequence,
                actual: data.sequence,
            });
        }

        Ok(data)
    }
}
