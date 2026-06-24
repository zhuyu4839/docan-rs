//! response of Service 10

use crate::{constants::LOG_TAG_SERVER, server::DoCanServer};
use iso14229_1::{
    request::Request,
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
    pub(crate) async fn _session_ctrl(
        &self,
        req: Request,
        cfg: &Configuration,
        data: Vec<u8>,
    ) -> Result<(), Iso14229Error> {
        let service = req.service();
        let resp = match req.sub_function() {
            Some(sf) => {
                match sf.function::<SessionType>() {
                    Ok(r#type) => {
                        self.session.change(r#type).await;
                        if r#type != Default::default() {
                            self.session.keep().await;
                        }

                        if sf.is_suppress_positive() {
                            return Ok(()); // suppress positive
                        } else {
                            Response::new(service, Some(r#type.into()), data, cfg)?
                        }
                    }
                    Err(e) => {
                        rsutil::warn!("{} failed to parse sub-function: {:?}", LOG_TAG_SERVER, e);
                        Response::new_negative(service, Code::IncorrectMessageLengthOrInvalidFormat)
                    }
                }
            }
            None => Response::new_negative(service, Code::GeneralReject),
        };

        self.transmit_response(resp, true).await;

        Ok(())
    }
}
