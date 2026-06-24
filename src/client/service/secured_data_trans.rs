//! response of Service 84

use crate::{client::DoCanClient, DoCanError, DoCanResult};
use iso14229_1::{request, response, *};
use iso15765_2::can::AddressType;
use rs_can::{CanDevice, CanFrame};
use std::{fmt::Display, hash::Hash};

impl<D, C, F> DoCanClient<D, C, F>
where
    D: CanDevice<Channel = C, Frame = F> + Clone + Send + 'static,
    C: Clone + Eq + Display + Hash + Send + Sync + 'static,
    F: CanFrame<Channel = C> + Clone + Display + 'static,
{
    pub(crate) async fn _secured_data_transmit(
        &self,
        apar: AdministrativeParameter,
        signature: SignatureEncryptionCalculation,
        anti_replay_cnt: u16,
        service: u8,
        service_data: Vec<u8>,
        signature_data: Vec<u8>,
    ) -> DoCanResult<response::SecuredDataTrans> {
        let data = request::SecuredDataTrans::new(
            apar,
            signature,
            anti_replay_cnt,
            service,
            service_data,
            signature_data,
        )
        .map_err(DoCanError::Iso14229Error)?;
        let cfg = self.context.get_cfg().await;
        let request = Self::make_request(Service::SecuredDataTrans, None, data, &cfg)?;

        let response = self
            .send_and_response(AddressType::Physical, request, None, &cfg)
            .await?;

        response
            .data::<response::SecuredDataTrans>(&cfg)
            .map_err(DoCanError::Iso14229Error)
    }
}
