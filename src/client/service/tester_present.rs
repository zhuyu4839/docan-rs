//! response of Service 3E

use crate::{client::DoCanClient, DoCanResult};
use iso14229_1::TesterPresentType;
use iso15765_2::can::AddressType;
use rs_can::{CanDevice, CanFrame};
use std::{fmt::Display, hash::Hash};

impl<D, C, F> DoCanClient<D, C, F>
where
    D: CanDevice<Channel = C, Frame = F> + Clone + Send + 'static,
    C: Clone + Eq + Display + Hash + Send + Sync + 'static,
    F: CanFrame<Channel = C> + Clone + Display + 'static,
{
    pub(crate) async fn _tester_present(
        &self,
        r#type: TesterPresentType,
        suppress_positive: bool,
        addr_type: AddressType,
    ) -> DoCanResult<()> {
        let cfg = self.context.get_cfg().await;
        let (service, request) =
            Self::tester_present_request(r#type, suppress_positive, &cfg).await?;

        let _ = self
            .suppress_positive_sr(
                addr_type,
                request,
                suppress_positive,
                Some((r#type.into(), service)),
                &cfg,
            )
            .await?;

        Ok(())
    }
}
