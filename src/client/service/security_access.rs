//! response of Service 27

use crate::{client::DoCanClient, DoCanError, DoCanResult};
use iso14229_1::Service;
use iso15765_2::can::AddressType;
use rs_can::{CanDevice, CanFrame};
use std::{fmt::Display, hash::Hash};

impl<D, C, F> DoCanClient<D, C, F>
where
    D: CanDevice<Channel = C, Frame = F> + Clone + Send + 'static,
    C: Clone + Eq + Display + Hash + Send + Sync + 'static,
    F: CanFrame<Channel = C> + Clone + Display + 'static,
{
    pub(crate) async fn _security_access(&self, level: u8, params: Vec<u8>) -> DoCanResult<Vec<u8>> {
        let service = Service::SecurityAccess;
        let cfg = self.context.get_cfg().await;
        let request = Self::make_request(service, Some(level), params, &cfg)?;

        let response = self
            .send_and_response(AddressType::Physical, request, Some((level, service)), &cfg)
            .await?;

        Ok(response.raw_data().to_vec())
    }

    pub(crate) async fn _unlock_security_access(
        &self,
        level: u8,
        params: Vec<u8>,
        salt: Vec<u8>,
    ) -> DoCanResult<()> {
        let service = Service::SecurityAccess;
        let cfg = self.context.get_cfg().await;
        let req = Self::make_request(service, Some(level), params, &cfg)?;

        let resp = self
            .send_and_response(AddressType::Physical, req, Some((level, service)), &cfg)
            .await?;

        let seed = resp.raw_data().to_vec();
        let algo = self
            .context
            .get_security_algo()
            .await
            .ok_or_else(|| DoCanError::OtherError("security algorithm required".into()))?;
        match algo(level, &seed, &salt)? {
            Some(data) => {
                let request = Self::make_request(service, Some(level + 1), data, &cfg)?;
                let _ = self
                    .send_and_response(
                        AddressType::Physical,
                        request,
                        Some((level + 1, service)),
                        &cfg,
                    )
                    .await?;

                Ok(())
            }
            None => Ok(()),
        }
    }
}
