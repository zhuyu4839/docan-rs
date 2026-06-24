//! response of Service 19

use iso14229_1::{request, response, DTCReportType, Service};
use iso15765_2::can::AddressType;
use rs_can::{CanDevice, CanFrame};
use std::{fmt::Display, hash::Hash};

use crate::{DoCanClient, DoCanResult};

impl<D, C, F> DoCanClient<D, C, F>
where
    D: CanDevice<Channel = C, Frame = F> + Clone + Send + 'static,
    C: Clone + Eq + Display + Hash + Send + Sync + 'static,
    F: CanFrame<Channel = C> + Clone + Display + 'static,
{
    pub(crate) async fn _read_dtc_info(
        &self,
        r#type: DTCReportType,
        data: request::DTCInfo,
    ) -> DoCanResult<response::DTCInfo> {
        let service = Service::ReadDTCInfo;
        let cfg = self.context.get_cfg().await;
        let request = Self::make_request(service, Some(r#type.into()), data, &cfg)?;

        self.send_and_parse(
            AddressType::Physical,
            request,
            Some((r#type.into(), service)),
            &cfg,
        )
        .await
    }
}
