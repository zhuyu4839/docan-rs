mod context;
mod service;

use crate::{constants::LOG_TAG_CLIENT, error::DoCanError};
use iso14229_1::{
    request::Request,
    response::{Code, Response},
    Configuration, Service, TesterPresentType, SUPPRESS_POSITIVE,
};
use iso15765_2::{
    can::{Address, AddressType, CanIsoTp},
    IsoTp, IsoTpError,
};
use rs_can::{CanDevice, CanFrame};
use rsutil::types::ByteOrder;
use std::{fmt::Display, hash::Hash};

#[derive(Clone)]
pub struct DoCanClient<D, C, F>
where
    D: CanDevice<Channel = C, Frame = F> + Clone + 'static,
    C: Display + Clone + Hash + Eq + 'static,
    F: CanFrame<Channel = C> + Clone + Display + 'static,
{
    isotp: CanIsoTp<D, C, F>,
    context: context::Context,
}

impl<D, C, F> DoCanClient<D, C, F>
where
    D: CanDevice<Channel = C, Frame = F> + Clone + Send + 'static,
    C: Display + Clone + Hash + Eq + Send + Sync + 'static,
    F: CanFrame<Channel = C> + Clone + Display + 'static,
{
    pub async fn new(
        device: D,
        channel: C,
        addr: Address,
        byte_order: ByteOrder,
        p2_offset: Option<u16>,
    ) -> Self {
        Self {
            isotp: CanIsoTp::new(device, channel, addr, false).await,
            context: context::Context::new(byte_order, p2_offset),
        }
    }

    #[inline(always)]
    pub fn byte_order(&self) -> ByteOrder {
        self.context.byte_order
    }

    #[inline(always)]
    fn make_request<T: Into<Vec<u8>>>(
        service: Service,
        sub_func: Option<u8>,
        data: T,
        cfg: &Configuration,
    ) -> Result<Request, DoCanError> {
        Request::new::<Vec<_>>(service, sub_func, data.into(), cfg)
            .map_err(DoCanError::Iso14229Error)
    }

    #[inline(always)]
    async fn send_and_parse<T>(
        &self,
        addr_type: AddressType,
        request: Request,
        sub_check: Option<(u8, Service)>,
        cfg: &Configuration,
    ) -> Result<T, DoCanError>
    where
        T: iso14229_1::ResponseData,
    {
        let response = self
            .send_and_response(addr_type, request, sub_check, cfg)
            .await?;
        response.data::<T>(cfg).map_err(DoCanError::Iso14229Error)
    }

    fn response_service_check(response: &Response, target: Service) -> Result<bool, DoCanError> {
        let service = response.service();
        if response.is_negative() {
            let nrc_code = response.nrc_code().map_err(DoCanError::Iso14229Error)?;
            match nrc_code {
                Code::RequestCorrectlyReceivedResponsePending => Ok(true),
                _ => Err(DoCanError::NRCError {
                    service,
                    code: nrc_code,
                }),
            }
        } else if service != target {
            Err(DoCanError::UnexpectedResponse {
                expect: target,
                actual: service,
            })
        } else {
            Ok(false)
        }
    }

    #[inline(always)]
    async fn suppress_positive_sr(
        &self,
        addr_type: AddressType,
        request: Request,
        suppress_positive: bool,
        sub_check: Option<(u8, Service)>,
        cfg: &Configuration,
    ) -> Result<Option<Response>, DoCanError> {
        match self.send_and_response(addr_type, request, None, cfg).await {
            Ok(r) => {
                if let Some((source, service)) = sub_check {
                    Self::sub_func_check(&r, source, service)?;
                }

                Ok(Some(r))
            }
            Err(e) => match e {
                DoCanError::IsoTpError(e) => match e {
                    IsoTpError::Timeout { .. } => {
                        if suppress_positive {
                            Ok(None)
                        } else {
                            Err(DoCanError::IsoTpError(e))
                        }
                    }
                    _ => Err(DoCanError::IsoTpError(e)),
                },
                _ => Err(e),
            },
        }
    }

    async fn send_and_response(
        &self,
        addr_type: AddressType,
        request: Request,
        sub_check: Option<(u8, Service)>,
        cfg: &Configuration,
    ) -> Result<Response, DoCanError> {
        let service = request.service();
        let data: Vec<_> = request.into();
        let timing = self.context.get_session_timing().await;
        let p2_offset = self.context.p2_offset;
        let _ = &self
            .isotp
            .transmit(addr_type, data)
            .await
            .map_err(DoCanError::IsoTpError)?;

        let data = &self
            .isotp
            .wait_data(timing.p2_ms() + p2_offset)
            .await
            .map_err(DoCanError::IsoTpError)?;
        let mut response = Response::try_from((data, cfg)).map_err(DoCanError::Iso14229Error)?;
        while Self::response_service_check(&response, service)? {
            rsutil::debug!(
                "{} tester present when {:?}",
                LOG_TAG_CLIENT,
                Code::RequestCorrectlyReceivedResponsePending
            );
            let (_, request) =
                Self::tester_present_request(TesterPresentType::Zero, true, cfg).await?;
            let data: Vec<_> = request.into();
            let _ = &self
                .isotp
                .transmit(addr_type, data)
                .await
                .map_err(DoCanError::IsoTpError)?;

            let data = &self
                .isotp
                .wait_data(timing.p2_star_ms())
                .await
                .map_err(DoCanError::IsoTpError)?;

            response = Response::try_from((data, cfg)).map_err(DoCanError::Iso14229Error)?;
        }

        if let Some((source, service)) = sub_check {
            Self::sub_func_check(&response, source, service)?;
        }

        Ok(response)
    }

    fn sub_func_check(response: &Response, source: u8, service: Service) -> Result<(), DoCanError> {
        match response.sub_function() {
            Some(v) => {
                // let source: u8 = session_type.into();
                let target = v.origin();
                if target != source {
                    Err(DoCanError::UnexpectedSubFunction {
                        service,
                        expect: source,
                        actual: target,
                    })
                } else {
                    Ok(())
                }
            }
            None => Err(DoCanError::OtherError(format!(
                "response of service `{}` got an empty sub-function",
                service
            ))),
        }
    }

    #[inline(always)]
    async fn tester_present_request(
        test_type: TesterPresentType,
        suppress_positive: bool,
        cfg: &Configuration,
    ) -> Result<(Service, Request), DoCanError> {
        let service = Service::TesterPresent;
        let mut sub_func = test_type.into();
        if suppress_positive {
            sub_func |= SUPPRESS_POSITIVE;
        }
        let request = Self::make_request(service, Some(sub_func), vec![], cfg)?;

        Ok((service, request))
    }
}

#[async_trait::async_trait]
impl<D, C, F> uds_trait::UdsLayer for DoCanClient<D, C, F>
where
    D: CanDevice<Channel = C, Frame = F> + Clone + Send + 'static,
    C: Display + Clone + Hash + Eq + Send + Sync + 'static,
    F: CanFrame<Channel = C> + Clone + Display + 'static,
{
    type Error = DoCanError;
    type Frame = F;
    type IsoTp = CanIsoTp<D, C, F>;

    fn tp_layer(&mut self) -> Self::IsoTp {
        self.isotp.clone()
    }

    async fn update_address(&self, address: Address) {
        self.isotp.update_address(address).await;
    }

    async fn update_security_algo(&self, algo: uds_trait::SecurityAlgo<Self::Error>) {
        self.context.set_security_algo(algo).await;
    }
}
