//! response of Service 2A

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
    pub(crate) async fn _read_data_by_period_identifier(
        &self,
        mode: request::TransmissionMode,
        did: Vec<u8>,
    ) -> DoCanResult<response::ReadDataByPeriodId> {
        let data =
            request::ReadDataByPeriodId::new(mode, did).map_err(DoCanError::Iso14229Error)?;
        let cfg = self.context.get_cfg().await;
        let request = Self::make_request(Service::ReadDataByPeriodId, None, data, &cfg)?;

        self.send_and_parse(AddressType::Physical, request, None, &cfg)
            .await
    }
}
