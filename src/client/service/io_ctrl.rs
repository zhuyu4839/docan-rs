//! response of Service 2F

use crate::{client::DoCanClient, DoCanError, DoCanResult};
use iso14229_1::{request, response, DataIdentifier, IOCtrlParameter, Service};
use iso15765_2::can::AddressType;
use rs_can::{CanDevice, CanFrame};
use std::{fmt::Display, hash::Hash};

impl<D, C, F> DoCanClient<D, C, F>
where
    D: CanDevice<Channel = C, Frame = F> + Clone + Send + 'static,
    C: Clone + Eq + Display + Hash + Send + Sync + 'static,
    F: CanFrame<Channel = C> + Clone + Display + 'static,
{
    pub(crate) async fn _io_control(
        &self,
        did: DataIdentifier,
        param: IOCtrlParameter,
        state: Vec<u8>,
        mask: Vec<u8>,
    ) -> DoCanResult<response::IOCtrl> {
        let cfg = self.context.get_cfg().await;
        let data = request::IOCtrl::new(did, param, state, mask, &cfg)
            .map_err(DoCanError::Iso14229Error)?;
        let request = Self::make_request(Service::IOCtrl, None, data, &cfg)?;

        self.send_and_parse(AddressType::Physical, request, None, &cfg)
            .await
    }
}
