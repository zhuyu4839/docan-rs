//! response of Service 22

use crate::{constants::LOG_TAG_SERVER, server::DoCanServer};
use iso14229_1::{
    request::{ReadDID, Request},
    response::{Code, Response},
    Configuration, Iso14229Error,
};
use rs_can::{CanDevice, CanFrame};
use std::fmt::Display;

impl<D, C, F> DoCanServer<D, C, F>
where
    D: CanDevice<Channel = C, Frame = F> + Clone + Send + 'static,
    C: Clone + Eq + Display + Send + Sync + 'static,
    F: CanFrame<Channel = C> + Clone + Display + 'static,
{
    pub(crate) async fn _read_did(
        &self,
        req: Request,
        cfg: &Configuration,
    ) -> Result<(), Iso14229Error> {
        let service = req.service();

        // Secured dataIdentifiers require a SecurityAccess service and therefore a non-default diagnostic session.
        let resp = match req.data::<ReadDID>(cfg) {
            Ok(ctx) => {
                let list = ctx.collect();
                if list.is_empty() {
                    Response::new_negative(service, Code::IncorrectMessageLengthOrInvalidFormat)
                } else {
                    let mut data = Vec::with_capacity(list.len());
                    for did in list {
                        match self.context.get_static_did(&did).await {
                            Some(val) => match self.context.get_static_did_sa_level(&did) {
                                Some(v) => {
                                    if self.session.get_security_access_level().await != v {
                                        return Ok(self
                                            .transmit_response(
                                                Response::new_negative(
                                                    service,
                                                    Code::SecurityAccessDenied,
                                                ),
                                                true,
                                            )
                                            .await);
                                    }

                                    let did_val: u16 = did.into();
                                    data.extend_from_slice(did_val.to_be_bytes().as_slice());
                                    data.extend_from_slice(val.as_ref());
                                }
                                None => {
                                    let did_val: u16 = did.into();
                                    data.extend_from_slice(did_val.to_be_bytes().as_slice());
                                    data.extend_from_slice(val.as_ref());
                                }
                            },
                            None => {
                                rsutil::warn!(
                                    "{} DID: {:?} is not configured",
                                    LOG_TAG_SERVER,
                                    did
                                );
                                return Ok(self
                                    .transmit_response(
                                        Response::new_negative(service, Code::RequestOutOfRange),
                                        true,
                                    )
                                    .await);
                            }
                        }
                    }

                    if data.is_empty() {
                        Response::new_negative(service, Code::RequestOutOfRange)
                    } else {
                        Response::new(service, None, data, cfg)?
                    }
                }
            }
            Err(e) => {
                rsutil::warn!("{} Failed to parse request data: {:?}", LOG_TAG_SERVER, e);
                Response::new_negative(service, Code::IncorrectMessageLengthOrInvalidFormat)
            }
        };

        self.transmit_response(resp, true).await;

        Ok(())
    }
}
