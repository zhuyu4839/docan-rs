//! response of Service 10

use crate::{client::DoCanClient, DoCanError, DoCanResult};
use iso14229_1::{response, *};
use iso15765_2::can::AddressType;
use rs_can::{CanDevice, CanFrame};
use std::{fmt::Display, hash::Hash};

impl<D, C, F> DoCanClient<D, C, F>
where
    D: CanDevice<Channel = C, Frame = F> + Clone + Send + 'static,
    C: Clone + Eq + Display + Hash + Send + Sync + 'static,
    F: CanFrame<Channel = C> + Clone + Display + 'static,
{
    pub(crate) async fn _session_ctrl(
        &self,
        r#type: SessionType,
        suppress_positive: bool,
        addr_type: AddressType,
    ) -> DoCanResult<()> {
        let service = Service::SessionCtrl;
        let mut sub_func: u8 = r#type.into();
        if suppress_positive {
            sub_func |= SUPPRESS_POSITIVE;
        }
        let cfg = self.context.get_cfg().await;
        let request = Self::make_request(service, Some(sub_func), vec![], &cfg)?;

        let timing = match self
            .suppress_positive_sr(
                addr_type,
                request,
                suppress_positive,
                Some((r#type.into(), service)),
                &cfg,
            )
            .await?
        {
            Some(resp) => Some(
                resp.data::<response::SessionCtrl>(&cfg)
                    .map_err(DoCanError::Iso14229Error)?
                    .0,
            ),
            None => None,
        };

        if let Some(timing) = timing {
            self.context.set_session_timing(timing).await;
        }

        Ok(())
    }
}
