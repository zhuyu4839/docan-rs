//! response of Service 3D

use crate::{constants::LOG_TAG_SERVER, server::DoCanServer};
use iso14229_1::{
    request::{self, Request},
    response::{self, Code, Response},
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
    pub(crate) async fn _write_mem_by_addr(
        &self,
        req: Request,
        cfg: &Configuration,
    ) -> Result<(), Iso14229Error> {
        let service = req.service();

        let resp = match self.session.get_session_type().await {
            SessionType::Extended => {
                let sa_level = self.session.get_security_access_level().await;
                if self.context.config.extend_sa_level != sa_level {
                    // security access denied
                    Response::new_negative(service, Code::SecurityAccessDenied)
                } else {
                    match req.data::<request::WriteMemByAddr>(cfg) {
                        Ok(ctx) => {
                            let data: Vec<_> = response::WriteMemByAddr(ctx.mem_loc).into();
                            Response::new(service, None, data, cfg)?
                        }
                        Err(e) => {
                            rsutil::warn!("{} failed to parse request data: {}", LOG_TAG_SERVER, e);
                            Response::new_negative(
                                service,
                                Code::IncorrectMessageLengthOrInvalidFormat,
                            )
                        }
                    }
                }
            }
            _ => Response::new_negative(service, Code::ServiceNotSupportedInActiveSession),
        };

        self.transmit_response(resp, true).await;

        Ok(())
    }
}
