//! response of Service 29

use crate::{client::DoCanClient, DoCanResult};
use iso14229_1::{request, response, *};
use iso15765_2::can::AddressType;
use rs_can::{CanDevice, CanFrame};
use std::{fmt::Display, hash::Hash};

impl<D, C, F> DoCanClient<D, C, F>
where
    D: CanDevice<Channel = C, Frame = F> + Clone + Send + 'static,
    C: Display + Clone + Hash + Eq + Send + Sync + 'static,
    F: CanFrame<Channel = C> + Clone + Display + 'static,
{
    pub(crate) async fn _authentication(
        &self,
        auth_task: AuthenticationTask,
        data: request::Authentication,
    ) -> DoCanResult<response::Authentication> {
        let service = Service::Authentication;
        let cfg = self.context.get_cfg().await;
        let request = Self::make_request(service, Some(auth_task.into()), data, &cfg)?;

        self.send_and_parse(
            AddressType::Physical,
            request,
            Some((auth_task.into(), service)),
            &cfg,
        )
        .await
    }
}
