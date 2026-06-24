//! response of Service 14

use iso14229_1::{request, utils::U24, Service};
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
    pub(crate) async fn _clear_dtc_info(
        &self,
        group: U24,
        mem_sel: Option<u8>,
        addr_type: AddressType,
    ) -> DoCanResult<()> {
        #[cfg(any(feature = "std2020"))]
        let data = request::ClearDiagnosticInfo::new(group, mem_sel);
        #[cfg(any(feature = "std2006", feature = "std2013"))]
        let data = request::ClearDiagnosticInfo::new(group);
        let cfg = self.context.get_cfg().await;
        let request = Self::make_request(Service::ClearDiagnosticInfo, None, data, &cfg)?;

        let _ = self
            .send_and_response(addr_type, request, None, &cfg)
            .await?;

        Ok(())
    }
}
