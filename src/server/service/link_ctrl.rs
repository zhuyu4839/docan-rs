//! response of Service 87

use crate::{constants::LOG_TAG_SERVER, server::DoCanServer};
use iso14229_1::{
    request::{self, Request},
    response::{Code, Response},
    Configuration, Iso14229Error, LinkCtrlType, SessionType,
};
use rs_can::{CanDevice, CanFrame};
use std::fmt::Display;

impl<D, C, F> DoCanServer<D, C, F>
where
    D: CanDevice<Channel = C, Frame = F> + Clone + Send + 'static,
    C: Clone + Eq + Display + Send + Sync + 'static,
    F: CanFrame<Channel = C> + Clone + Display + 'static,
{
    pub(crate) async fn _link_ctrl(
        &self,
        req: Request,
        cfg: &Configuration,
    ) -> Result<(), Iso14229Error> {
        let service = req.service();

        let resp = if self.session.get_session_type().await == SessionType::Default {
            Response::new_negative(service, Code::ServiceNotSupportedInActiveSession)
        } else {
            match req.sub_function() {
                Some(sf) => match req.data::<request::LinkCtrl>(cfg) {
                    Ok(data) => match sf.function::<LinkCtrlType>() {
                        Ok(r#type) => {
                            rsutil::info!(
                                "{} LinkCtrl request: {:?}, sub-function: {:?}",
                                LOG_TAG_SERVER,
                                data,
                                r#type
                            );
                            match r#type {
                                LinkCtrlType::VerifyModeTransitionWithFixedParameter
                                | LinkCtrlType::VerifyModeTransitionWithSpecificParameter => {
                                    self.session.arm_link_control_verify().await;
                                    if sf.is_suppress_positive() {
                                        return Ok(());
                                    } else {
                                        Response::new(service, Some(sf.into()), vec![], cfg)?
                                    }
                                }
                                LinkCtrlType::TransitionMode => {
                                    if !self.session.consume_link_control_verify().await {
                                        Response::new_negative(service, Code::RequestSequenceError)
                                    } else if sf.is_suppress_positive() {
                                        return Ok(());
                                    } else {
                                        Response::new(
                                            service,
                                            Some(LinkCtrlType::TransitionMode.into()),
                                            vec![],
                                            cfg,
                                        )?
                                    }
                                }
                                _ => Response::new_negative(service, Code::SubFunctionNotSupported),
                            }
                        }
                        Err(e) => {
                            rsutil::warn!(
                                "{} failed to parse request data: {:?}",
                                LOG_TAG_SERVER,
                                e
                            );
                            Response::new_negative(
                                service,
                                Code::IncorrectMessageLengthOrInvalidFormat,
                            )
                        }
                    },
                    Err(e) => {
                        rsutil::warn!("{} failed to parse request data: {:?}", LOG_TAG_SERVER, e);
                        Response::new_negative(service, Code::IncorrectMessageLengthOrInvalidFormat)
                    }
                },
                None => {
                    Response::new_negative(service, Code::IncorrectMessageLengthOrInvalidFormat)
                }
            }
        };

        self.transmit_response(resp, true).await;

        Ok(())
    }
}
