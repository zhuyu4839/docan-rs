//! response of Service 86

use crate::{client::DoCanClient, DoCanResult};

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
    pub(crate) async fn _response_on_event(
        &self,
        data: request::ResponseOnEvent,
    ) -> DoCanResult<response::ResponseOnEvent> {
        let cfg = self.context.get_cfg().await;
        let request = Self::make_request(Service::ResponseOnEvent, None, data, &cfg)?;

        self.send_and_parse(AddressType::Physical, request, None, &cfg)
            .await
    }
}
