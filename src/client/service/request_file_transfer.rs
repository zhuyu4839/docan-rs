//! response of Service 38

use crate::{client::DoCanClient, DoCanError, DoCanResult};
use iso14229_1::{request, response, ModeOfOperation, Service};
use iso15765_2::can::AddressType;
use rs_can::{CanDevice, CanFrame};
use std::{fmt::Display, hash::Hash};

impl<D, C, F> DoCanClient<D, C, F>
where
    D: CanDevice<Channel = C, Frame = F> + Clone + Send + 'static,
    C: Clone + Eq + Display + Hash + Send + Sync + 'static,
    F: CanFrame<Channel = C> + Clone + Display + 'static,
{
    pub(crate) async fn _request_file_transfer(
        &self,
        operation: ModeOfOperation,
        data: request::RequestFileTransfer,
    ) -> DoCanResult<response::RequestFileTransfer> {
        let service = Service::RequestFileTransfer;
        let sub_func = operation.into();
        let cfg = self.context.get_cfg().await;
        let request = Self::make_request(service, Some(sub_func), data, &cfg)?;

        let response = self
            .send_and_response(
                AddressType::Physical,
                request,
                Some((operation.into(), service)),
                &cfg,
            )
            .await?;

        response
            .data::<response::RequestFileTransfer>(&cfg)
            .map_err(DoCanError::Iso14229Error)
    }
}
