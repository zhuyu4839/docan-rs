//! response of Service 36

use crate::{constants::LOG_TAG_SERVER, server::DoCanServer};
use iso14229_1::{
    request::{self, Request},
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
    pub(crate) async fn _transfer_data(
        &self,
        req: Request,
        cfg: &Configuration,
    ) -> Result<(), Iso14229Error> {
        let service = req.service();
        let resp = if self.session.get_session_type().await == Default::default() {
            Response::new_negative(service, Code::ServiceNotSupportedInActiveSession)
        } else {
            match req.data::<request::TransferData>(cfg) {
                Ok(v) => match self.context.transfer_data(v.sequence, &v.data).await {
                    Ok(data) => Response::new(service, None, Vec::<u8>::from(data), cfg)?,
                    Err(code) => Response::new_negative(service, code),
                },
                Err(e) => {
                    rsutil::warn!("{} Failed to parse request data: {:?}", LOG_TAG_SERVER, e);
                    Response::new_negative(service, Code::IncorrectMessageLengthOrInvalidFormat)
                }
            }
        };

        self.transmit_response(resp, true).await;

        Ok(())
    }
}
