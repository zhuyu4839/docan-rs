//! response of Service 85

use crate::{constants::LOG_TAG_SERVER, server::DoCanServer};
use iso14229_1::{
    request::{self, Request},
    response::{Code, Response},
    Configuration, DTCSettingType, Iso14229Error,
};
use rs_can::{CanDevice, CanFrame};
use std::fmt::Display;

impl<D, C, F> DoCanServer<D, C, F>
where
    D: CanDevice<Channel = C, Frame = F> + Clone + Send + 'static,
    C: Clone + Eq + Display + Send + Sync + 'static,
    F: CanFrame<Channel = C> + Clone + Display + 'static,
{
    pub(crate) async fn _ctrl_dtc_setting(
        &self,
        req: Request,
        cfg: &Configuration,
    ) -> Result<(), Iso14229Error> {
        let service = req.service();

        let resp = if self.session.get_session_type().await == Default::default() {
            Response::new_negative(service, Code::ServiceNotSupportedInActiveSession)
        } else {
            match req.sub_function() {
                Some(sf) => match req.data::<request::CtrlDTCSetting>(cfg) {
                    Ok(data) => match sf.function::<DTCSettingType>() {
                        Ok(r#type) => {
                            rsutil::info!(
                                "{} receive request on service: {}, with sub-function: {:?}, and data: {:?}",
                                LOG_TAG_SERVER,
                                service,
                                r#type,
                                data
                            );
                            match self.context.set_dtc_setting(r#type).await {
                                Ok(applied) => {
                                    if sf.is_suppress_positive() {
                                        return Ok(());
                                    } else {
                                        Response::new(service, Some(applied.into()), vec![], cfg)?
                                    }
                                }
                                Err(code) => Response::new_negative(service, code),
                            }
                        }
                        Err(e) => {
                            rsutil::warn!(
                                "{} Failed to parse sub-function: {:?}",
                                LOG_TAG_SERVER,
                                e
                            );
                            Response::new_negative(service, Code::SubFunctionNotSupported)
                        }
                    },
                    Err(e) => {
                        rsutil::warn!(
                            "{} can't parse data on service: {}, because of: {}",
                            LOG_TAG_SERVER,
                            service,
                            e
                        );
                        Response::new_negative(service, Code::IncorrectMessageLengthOrInvalidFormat)
                    }
                },
                None => {
                    rsutil::warn!(
                        "{} can't get sub-function on service: {}",
                        LOG_TAG_SERVER,
                        service
                    );
                    Response::new_negative(service, Code::IncorrectMessageLengthOrInvalidFormat)
                }
            }
        };

        self.transmit_response(resp, true).await;

        Ok(())
    }
}
