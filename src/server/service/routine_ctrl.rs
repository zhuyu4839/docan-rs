//! response of Service 31

use crate::{constants::LOG_TAG_SERVER, server::DoCanServer};
use iso14229_1::{
    request::{Request, RoutineCtrl},
    response::{Code, Response},
    Configuration, Iso14229Error, RoutineCtrlType, SessionType,
};
use rs_can::{CanDevice, CanFrame};
use std::fmt::Display;

impl<D, C, F> DoCanServer<D, C, F>
where
    D: CanDevice<Channel = C, Frame = F> + Clone + Send + 'static,
    C: Clone + Eq + Display + Send + Sync + 'static,
    F: CanFrame<Channel = C> + Clone + Display + 'static,
{
    pub(crate) async fn _routine_ctrl(
        &self,
        req: Request,
        cfg: &Configuration,
    ) -> Result<(), Iso14229Error> {
        let service = req.service();

        let resp = if self.session.get_session_type().await == SessionType::Default {
            Response::new_negative(service, Code::ServiceNotSupportedInActiveSession)
        } else {
            match req.data::<RoutineCtrl>(cfg) {
                Ok(val) => match req.sub_function() {
                    Some(sf) => match sf.function::<RoutineCtrlType>() {
                        Ok(r#type) => match self
                            .context
                            .routine_ctrl(r#type, val.routine_id, &val.option_record)
                            .await
                        {
                            Ok(result) => {
                                if sf.is_suppress_positive() {
                                    return Ok(());
                                } else {
                                    Response::new(
                                        service,
                                        Some(r#type.into()),
                                        Vec::<u8>::from(result),
                                        cfg,
                                    )?
                                }
                            }
                            Err(code) => Response::new_negative(service, code),
                        },
                        Err(e) => {
                            rsutil::warn!(
                                "{} Failed to parse sub-function: {:?}",
                                LOG_TAG_SERVER,
                                e
                            );
                            Response::new_negative(service, Code::SubFunctionNotSupported)
                        }
                    },
                    None => {
                        Response::new_negative(service, Code::IncorrectMessageLengthOrInvalidFormat)
                    }
                },
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
