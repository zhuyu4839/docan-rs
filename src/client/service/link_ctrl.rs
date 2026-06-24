//! response of Service 87

use crate::{client::DoCanClient, DoCanResult};
use iso14229_1::{request, LinkCtrlType, Service, SUPPRESS_POSITIVE};
use iso15765_2::can::AddressType;
use rs_can::{CanDevice, CanFrame};
use std::{fmt::Display, hash::Hash};

impl<D, C, F> DoCanClient<D, C, F>
where
    D: CanDevice<Channel = C, Frame = F> + Clone + Send + 'static,
    C: Clone + Eq + Display + Hash + Send + Sync + 'static,
    F: CanFrame<Channel = C> + Clone + Display + 'static,
{
    pub(crate) async fn _link_control(
        &self,
        r#type: LinkCtrlType,
        data: request::LinkCtrl,
        suppress_positive: bool,
    ) -> DoCanResult<()> {
        let service = Service::LinkCtrl;
        let mut sub_func = r#type.into();
        if suppress_positive {
            sub_func |= SUPPRESS_POSITIVE;
        }
        let cfg = self.context.get_cfg().await;
        let request = Self::make_request(Service::LinkCtrl, Some(sub_func), data, &cfg)?;

        let _ = self
            .suppress_positive_sr(
                AddressType::Physical,
                request,
                suppress_positive,
                Some((r#type.into(), service)),
                &cfg,
            )
            .await?;

        Ok(())
    }
}
