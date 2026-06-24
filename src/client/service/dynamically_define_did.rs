//! response of Service 2C

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
    pub(crate) async fn _dynamically_define_data_by_identifier(
        &self,
        r#type: DefinitionType,
        data: request::DynamicallyDefineDID,
        suppress_positive: bool,
    ) -> DoCanResult<Option<response::DynamicallyDefineDID>> {
        let service = Service::DynamicalDefineDID;
        let mut sub_func = r#type.into();
        if suppress_positive {
            sub_func |= SUPPRESS_POSITIVE;
        }
        let cfg = self.context.get_cfg().await;
        let request = Self::make_request(Service::DynamicalDefineDID, Some(sub_func), data, &cfg)?;

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
