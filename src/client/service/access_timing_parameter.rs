//! response of Service 83

use crate::{constants::LOG_TAG_SERVER, server::DoCanServer};
use iso14229_1::{
    request::{self, Request},
    response::{Code, Response},
    DidConfig, Iso14229Error, TimingParameterAccessType,
};
use rs_can::{CanDevice, CanFrame};
use std::fmt::Display;

impl<D, C, F> DoCanServer<D, C, F>
where
    D: CanDevice<Channel = C, Frame = F> + Clone + Send + 'static,
    C: Clone + Eq + Display + Send + 'static,
    F: CanFrame<Channel = C> + Clone + Display + 'static,
{
    pub(crate) async fn _access_timing_parameter(
        &self,
        r#type: request::TimingParameterAccessType,
        parameter: Vec<u8>,
        suppress_positive: bool,
    ) -> DoCanResult<Option<response::AccessTimingParameter>> {
        let service = Service::AccessTimingParam;
        let mut sub_func = r#type.into();
        if suppress_positive {
            sub_func |= SUPPRESS_POSITIVE;
        }
        let cfg = self.context.get_cfg().await;
        let request =
            Self::make_request(Service::AccessTimingParam, Some(sub_func), parameter, &cfg)?;

        let response = self
            .suppress_positive_sr(
                AddressType::Physical,
                request,
                suppress_positive,
                Some((r#type.into(), service)),
                &cfg,
            )
            .await?;

        match response {
            Some(v) => Ok(Some(v.data(&cfg).map_err(DoCanError::Iso14229Error)?)),
            None => Ok(None),
        }
    }
}
