//! response of Service 2A

use crate::{constants::LOG_TAG_SERVER, server::DoCanServer};
use iso14229_1::{
    request::{self, Request},
    response::{Code, Response},
    Configuration, Iso14229Error, SessionType,
};
use rs_can::{CanDevice, CanFrame};
use std::fmt::Display;

impl<D, C, F> DoCanServer<D, C, F>
where
    D: CanDevice<Channel = C, Frame = F> + Clone + Send + 'static,
    C: Clone + Eq + Display + Send + Sync + 'static,
    F: CanFrame<Channel = C> + Clone + Display + 'static,
{
    pub(crate) async fn _read_data_by_pid(
        &self,
        req: Request,
        cfg: &Configuration,
    ) -> Result<(), Iso14229Error> {
        let service = req.service();

        let resp = if self.session.get_session_type().await == SessionType::Default {
            Response::new_negative(service, Code::ServiceNotSupportedInActiveSession)
        } else {
            match req.data::<request::ReadDataByPeriodId>(cfg) {
                Ok(_) => {
                    // let mode = ctx.mode;
                    // let did = ctx.did;
                    Response::new_negative(service, Code::ServiceNotSupported)
                }
                Err(e) => {
                    rsutil::warn!("{} failed to parse request data: {:?}", LOG_TAG_SERVER, e);
                    Response::new_negative(service, Code::IncorrectMessageLengthOrInvalidFormat)
                }
            }
        };

        self.transmit_response(resp, true).await;

        Ok(())
    }
}
