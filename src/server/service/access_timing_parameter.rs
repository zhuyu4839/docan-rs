//! response of Service 83

use crate::{constants::LOG_TAG_SERVER, server::DoCanServer};
use iso14229_1::{
    request::{self, Request},
    response::{Code, Response},
    Configuration, Iso14229Error, TimingParameterAccessType,
};
use rs_can::{CanDevice, CanFrame};
use std::fmt::Display;

impl<D, C, F> DoCanServer<D, C, F>
where
    D: CanDevice<Channel = C, Frame = F> + Clone + Send + 'static,
    C: Clone + Eq + Display + Send + Sync + 'static,
    F: CanFrame<Channel = C> + Clone + Display + 'static,
{
    pub(crate) async fn _access_timing_parameter(
        &self,
        req: Request,
        cfg: &Configuration,
    ) -> Result<(), Iso14229Error> {
        let service = req.service();

        let resp = if self.session.get_session_type().await == Default::default() {
            Response::new_negative(service, Code::ServiceNotSupportedInActiveSession)
        } else {
            match req.sub_function() {
                Some(sf) => match req.data::<request::AccessTimingParameter>(cfg) {
                    Ok(data) => match sf.function::<TimingParameterAccessType>() {
                        Ok(r#type) => {
                            match self
                                .context
                                .access_timing_parameter(r#type, &data.data)
                                .await
                            {
                                Ok(v) => {
                                    if sf.is_suppress_positive() {
                                        return Ok(());
                                    } else {
                                        Response::new(
                                            service,
                                            Some(r#type.into()),
                                            Vec::<u8>::from(v),
                                            cfg,
                                        )?
                                    }
                                }
                                Err(code) => Response::new_negative(service, code),
                            }
                        }
                        Err(e) => {
                            rsutil::warn!(
                                "{} can't parse sub-function on service: {}, because of: {}",
                                LOG_TAG_SERVER,
                                service,
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
