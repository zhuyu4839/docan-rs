//! response of Service 3E

use crate::{constants::LOG_TAG_SERVER, server::DoCanServer};
use iso14229_1::{
    request::Request,
    response::{Code, Response},
    Configuration, Iso14229Error, TesterPresentType,
};
use rs_can::{CanDevice, CanFrame};
use std::fmt::Display;

impl<D, C, F> DoCanServer<D, C, F>
where
    D: CanDevice<Channel = C, Frame = F> + Clone + Send + 'static,
    C: Clone + Eq + Display + Send + Sync + 'static,
    F: CanFrame<Channel = C> + Clone + Display + 'static,
{
    pub(crate) async fn _tester_present(
        &self,
        req: Request,
        cfg: &Configuration,
    ) -> Result<(), Iso14229Error> {
        let service = req.service();
        let resp = match req.sub_function() {
            Some(sf) => {
                if sf.is_suppress_positive() {
                    if self.session.get_session_type().await != Default::default() {
                        self.session.keep().await;
                    }
                    return Ok(()); // suppress positive
                } else {
                    match sf.function::<TesterPresentType>() {
                        Ok(r#type) => {
                            if self.session.get_session_type().await != Default::default() {
                                self.session.keep().await;
                            }
                            Response::new(service, Some(r#type.into()), vec![], cfg)?
                        }
                        Err(e) => {
                            rsutil::warn!(
                                "{} Failed to parse sub-function: {:?}",
                                LOG_TAG_SERVER,
                                e
                            );
                            Response::new_negative(service, Code::SubFunctionNotSupported)
                        }
                    }
                }
            }
            None => Response::new_negative(service, Code::GeneralReject),
        };

        self.transmit_response(resp, true).await;

        Ok(())
    }
}
