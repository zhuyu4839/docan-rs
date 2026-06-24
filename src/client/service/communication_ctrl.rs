//! response of Service 28

use crate::{client::DoCanClient, DoCanError, DoCanResult};
use iso14229_1::{request, *};
use iso15765_2::can::AddressType;
use rs_can::{CanDevice, CanFrame};
use std::{fmt::Display, hash::Hash};

impl<D, C, F> DoCanClient<D, C, F>
where
    D: CanDevice<Channel = C, Frame = F> + Clone + Send + 'static,
    C: Clone + Eq + Display + Hash + Send + Sync + 'static,
    F: CanFrame<Channel = C> + Clone + Display + 'static,
{
    pub(crate) async fn _communication_control(
        &self,
        ctrl_type: CommunicationCtrlType,
        comm_type: CommunicationType,
        node_id: Option<request::NodeId>,
        suppress_positive: bool,
        addr_type: AddressType,
    ) -> DoCanResult<()> {
        let service = Service::CommunicationCtrl;
        let mut sub_func = ctrl_type.into();
        if suppress_positive {
            sub_func |= SUPPRESS_POSITIVE;
        }
        let data = request::CommunicationCtrl::new(ctrl_type, comm_type, node_id)
            .map_err(DoCanError::Iso14229Error)?;
        let cfg = self.context.get_cfg().await;
        let req = Self::make_request(service, Some(sub_func), data, &cfg)?;

        let _ = self
            .suppress_positive_sr(
                addr_type,
                req,
                suppress_positive,
                Some((ctrl_type.into(), service)),
                &cfg,
            )
            .await?;

        Ok(())
    }
}
