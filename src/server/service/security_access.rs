//! response of Service 27

use crate::{
    constants::LOG_TAG_SERVER,
    server::{util, DoCanServer},
};
use bytes::Bytes;
use iso14229_1::{
    request::Request,
    response::{Code, Response},
    Configuration, Iso14229Error, SecurityAccessLevel,
};
use rs_can::{CanDevice, CanFrame};
use std::fmt::Display;

impl<D, C, F> DoCanServer<D, C, F>
where
    D: CanDevice<Channel = C, Frame = F> + Clone + Send + 'static,
    C: Clone + Eq + Display + Send + Sync + 'static,
    F: CanFrame<Channel = C> + Clone + Display + 'static,
{
    pub(crate) async fn _security_access(
        &self,
        req: Request,
        cfg: &Configuration,
    ) -> Result<(), Iso14229Error> {
        let service = req.service();
        let resp = match req.sub_function() {
            Some(sf) => match sf.function::<SecurityAccessLevel>() {
                Ok(v) => {
                    let mut guard = self.context.sa_ctx.lock().await;
                    if v.is_request_seed() {
                        let data = util::gen_seed(self.context.config.seed_len);
                        let resp = Response::new(service, Some(v.into()), &data, cfg)?;
                        let _ = guard.replace((v.into(), Bytes::from(data)));

                        resp
                    } else {
                        match guard.take() {
                            Some(ctx) => {
                                let level: u8 = v.into();
                                if level - 1 != ctx.0 {
                                    Response::new_negative(service, Code::ConditionsNotCorrect)
                                } else {
                                    match self.context.get_security_algo().await {
                                        Some(algo) => {
                                            let level = ctx.0;
                                            let response_level: u8 = v.into();
                                            let seed = ctx.1.as_ref();
                                            let salt = self.context.get_security_salt();
                                            match algo(level, seed, salt.as_ref()) {
                                                Ok(v) => match v {
                                                    Some(v) => {
                                                        if req.raw_data() != v.as_slice() {
                                                            Response::new_negative(
                                                                service,
                                                                Code::InvalidKey,
                                                            )
                                                        } else {
                                                            self.session
                                                                .set_security_access_level(level)
                                                                .await;
                                                            Response::new(
                                                                service,
                                                                Some(response_level),
                                                                vec![],
                                                                cfg,
                                                            )?
                                                        }
                                                    }
                                                    None => Response::new_negative(
                                                        service,
                                                        Code::SecurityAccessDenied,
                                                    ),
                                                },
                                                Err(e) => {
                                                    rsutil::warn!(
                                                        "{} error: {} when calculator sa key",
                                                        LOG_TAG_SERVER,
                                                        e
                                                    );
                                                    Response::new_negative(
                                                        service,
                                                        Code::GeneralReject,
                                                    )
                                                }
                                            }
                                        }
                                        None => Response::new_negative(
                                            service,
                                            Code::ConditionsNotCorrect,
                                        ),
                                    }
                                }
                            }
                            None => Response::new_negative(service, Code::SubFunctionNotSupported),
                        }
                    }
                }
                Err(e) => {
                    rsutil::warn!("{} Failed to parse access level: {:?}", LOG_TAG_SERVER, e);
                    Response::new_negative(service, Code::SubFunctionNotSupported)
                }
            },
            None => Response::new_negative(service, Code::IncorrectMessageLengthOrInvalidFormat),
        };

        self.transmit_response(resp, true).await;

        Ok(())
    }
}
