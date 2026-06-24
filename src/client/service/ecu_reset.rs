//! response of Service 11

use crate::{client::DoCanClient, DoCanError, DoCanResult};
use iso14229_1::{response, *};
use iso15765_2::can::AddressType;
use rs_can::{CanDevice, CanFrame};
use std::{fmt::Display, hash::Hash, time::Duration};

impl<D, C, F> DoCanClient<D, C, F>
where
    D: CanDevice<Channel = C, Frame = F> + Clone + Send + 'static,
    C: Clone + Eq + Display + Hash + Send + Sync + 'static,
    F: CanFrame<Channel = C> + Clone + Display + 'static,
{
    pub(crate) async fn _ecu_reset(
        &self,
        r#type: ECUResetType,
        suppress_positive: bool,
        addr_type: AddressType,
    ) -> DoCanResult<()> {
        let service = Service::ECUReset;
        let mut sub_func: u8 = r#type.into();
        if suppress_positive {
            sub_func |= SUPPRESS_POSITIVE;
        }
        let cfg = self.context.get_cfg().await;
        let request = Self::make_request(service, Some(sub_func), vec![], &cfg)?;

        if let Some(response) = self
            .suppress_positive_sr(
                addr_type,
                request,
                suppress_positive,
                Some((r#type.into(), service)),
                &cfg,
            )
            .await?
        {
            let resp = response
                .data::<response::ECUReset>(&cfg)
                .map_err(DoCanError::Iso14229Error)?;
            if let Some(seconds) = resp.second {
                tokio::time::sleep(Duration::from_secs(seconds as u64)).await;
            }
        }

        Ok(())
    }
}
