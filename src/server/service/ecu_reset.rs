//! response of Service 11

use crate::{constants::LOG_TAG_SERVER, server::DoCanServer};
use iso14229_1::{
    request::Request,
    response::{Code, Response},
    Configuration, ECUResetType, Iso14229Error,
};
use rs_can::{CanDevice, CanFrame};
use std::fmt::Display;

impl<D, C, F> DoCanServer<D, C, F>
where
    D: CanDevice<Channel = C, Frame = F> + Clone + Send + 'static,
    C: Clone + Eq + Display + Send + Sync + 'static,
    F: CanFrame<Channel = C> + Clone + Display + 'static,
{
    pub(crate) async fn _ecu_reset(
        &self,
        req: Request,
        cfg: &Configuration,
    ) -> Result<(), Iso14229Error> {
        let service = req.service();
        let resp = match req.sub_function() {
            Some(sf) => {
                match sf.function::<ECUResetType>() {
                    Ok(r#type) => {
                        self.context.reset().await;
                        self.session.reset().await;
                        if sf.is_suppress_positive() {
                            return Ok(()); // suppress positive
                        } else {
                            let data = match r#type {
                                ECUResetType::EnableRapidPowerShutDown => vec![1],
                                _ => vec![],
                            };
                            Response::new(service, Some(r#type.into()), data, cfg)?
                        }
                    }
                    Err(e) => {
                        rsutil::warn!("{} Failed to parse sub-function: {:?}", LOG_TAG_SERVER, e);
                        Response::new_negative(service, Code::SubFunctionNotSupported)
                    }
                }
            }
            None => Response::new_negative(service, Code::IncorrectMessageLengthOrInvalidFormat),
        };

        self.transmit_response(resp, true).await;

        Ok(())
    }
}
