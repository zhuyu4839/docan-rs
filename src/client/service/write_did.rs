//! response of Service 2E

use crate::{client::DoCanClient, DoCanResult};
use iso14229_1::{request, DIDData, DataIdentifier, Service};
use iso15765_2::can::AddressType;
use rs_can::{CanDevice, CanFrame};
use std::{fmt::Display, hash::Hash};

impl<D, C, F> DoCanClient<D, C, F>
where
    D: CanDevice<Channel = C, Frame = F> + Clone + Send + 'static,
    C: Clone + Eq + Display + Hash + Send + Sync + 'static,
    F: CanFrame<Channel = C> + Clone + Display + 'static,
{
    pub(crate) async fn _write_data_by_identifier(
        &self,
        did: DataIdentifier,
        data: Vec<u8>,
    ) -> DoCanResult<()> {
        let data = request::WriteDID(DIDData { did, data });
        let cfg = self.context.get_cfg().await;
        let request = Self::make_request(Service::WriteDID, None, data, &cfg)?;

        let _ = self
            .send_and_response(AddressType::Physical, request, None, &cfg)
            .await?;

        Ok(())
    }
}
