mod context;
mod service;
mod session;
mod util;

use crate::{constants::LOG_TAG_SERVER, server::session::SessionManager, DoCanError};
use iso14229_1::{response::SessionTiming, Configuration, DataIdentifier};
use rsutil::types::ByteOrder;
use serde::{Deserialize, Deserializer};
use std::collections::HashMap;

use iso14229_1::{
    request::Request,
    response::{Code, Response},
    Iso14229Error, Service,
};
use iso15765_2::{
    can::{Address, AddressType, CanIsoTp},
    IsoTp, IsoTpError,
};
use rs_can::{CanDevice, CanFrame};
use std::{fmt::Display, sync::Arc};
use tokio::task::JoinHandle;

pub type DidSaLevel = HashMap<DataIdentifier, u8>;

fn did_sa_level_deserialize<'de, D>(deserializer: D) -> Result<DidSaLevel, D::Error>
where
    D: Deserializer<'de>,
{
    let raw_map: HashMap<u16, u8> = HashMap::deserialize(deserializer)?;

    let res = raw_map
        .into_iter()
        .map(|(k, v)| (DataIdentifier::from(k), v))
        .collect::<HashMap<_, _>>();

    Ok(res)
}

#[allow(unused)]
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub(crate) address: Address,
    pub(crate) timing: SessionTiming,
    /// extend session security access level
    pub(crate) extend_sa_level: u8,
    /// program session security access level
    pub(crate) program_sa_level: u8,
    pub(crate) seed_len: usize,
    pub(crate) sa_salt: Vec<u8>,
    pub(crate) cfg: Configuration,
    #[serde(deserialize_with = "did_sa_level_deserialize")]
    pub(crate) did_sa_level: DidSaLevel,
    pub(crate) byte_order: ByteOrder,
}

#[derive(Clone)]
pub struct DoCanServer<D, C, F> {
    isotp: CanIsoTp<D, C, F>,
    session: SessionManager,
    context: context::Context,
    handles: Vec<Arc<JoinHandle<()>>>,
}

impl<D, C, F> DoCanServer<D, C, F>
where
    D: CanDevice<Channel = C, Frame = F> + Clone + Send + 'static,
    C: Clone + Eq + Display + Send + Sync + 'static,
    F: CanFrame<Channel = C> + Clone + Display + 'static,
{
    pub async fn new(device: D, channel: C) -> Result<Self, DoCanError> {
        let context = context::Context::new().await?;
        Ok(Self {
            isotp: CanIsoTp::new(device, channel, context.config.address, true).await,
            session: SessionManager::new(None),
            context,
            handles: Default::default(),
        })
    }

    pub(crate) async fn server(&mut self) {
        loop {
            let timing = self.context.get_active_timing().await;
            let cfg = self.context.get_cfg().clone();
            if let Ok(data) = self.isotp.wait_data(timing.p2_ms()).await {
                // rsutil::info!("{} Received data: {}", LOG_TAG_SERVER, hex::encode(&data));
                match data.len() {
                    0 => {}
                    _ => match Service::try_from(data[0]) {
                        Ok(service) => match Request::try_from((service, &data[1..], &cfg)) {
                            Ok(req) => {
                                if let Err(e) = match service {
                                    Service::SessionCtrl => {
                                        self._session_ctrl(req, &cfg, timing.into()).await
                                    }
                                    Service::ECUReset => self._ecu_reset(req, &cfg).await,
                                    Service::ClearDiagnosticInfo => {
                                        self._clear_diagnostic_info(req, &cfg).await
                                    }
                                    Service::ReadDTCInfo => self._read_dtc_info(req, &cfg).await,
                                    Service::ReadDID => self._read_did(req, &cfg).await,
                                    Service::ReadMemByAddr => {
                                        self._read_mem_by_addr(req, &cfg).await
                                    }
                                    Service::ReadScalingDID => {
                                        self._read_scaling_did(req, &cfg).await
                                    }
                                    Service::SecurityAccess => {
                                        self._security_access(req, &cfg).await
                                    }
                                    Service::CommunicationCtrl => {
                                        self._communication_ctrl(req, &cfg).await
                                    }
                                    #[cfg(any(feature = "std2020"))]
                                    Service::Authentication => self._authentication(req, &cfg).await,
                                    Service::ReadDataByPeriodId => {
                                        self._read_data_by_pid(req, &cfg).await
                                    }
                                    Service::DynamicalDefineDID => {
                                        self._dynamically_define_did(req, &cfg).await
                                    }
                                    Service::WriteDID => self._write_did(req, &cfg).await,
                                    Service::IOCtrl => self._io_ctrl(req, &cfg).await,
                                    Service::RoutineCtrl => self._routine_ctrl(req, &cfg).await,
                                    Service::RequestDownload => {
                                        self._request_download(req, &cfg).await
                                    }
                                    Service::RequestUpload => self._request_upload(req, &cfg).await,
                                    Service::TransferData => self._transfer_data(req, &cfg).await,
                                    Service::RequestTransferExit => {
                                        self._request_transfer_exit(req, &cfg).await
                                    }
                                    #[cfg(any(feature = "std2013", feature = "std2020"))]
                                    Service::RequestFileTransfer => {
                                        self._request_file_transfer(req, &cfg).await
                                    }
                                    Service::WriteMemByAddr => {
                                        self._write_mem_by_addr(req, &cfg).await
                                    }
                                    Service::TesterPresent => self._tester_present(req, &cfg).await,
                                    #[cfg(any(feature = "std2006", feature = "std2013"))]
                                    Service::AccessTimingParam => {
                                        self._access_timing_parameter(req, &cfg).await
                                    }
                                    Service::SecuredDataTrans => {
                                        self._secured_data_trans(req, &cfg).await
                                    }
                                    Service::CtrlDTCSetting => {
                                        self._ctrl_dtc_setting(req, &cfg).await
                                    }
                                    Service::ResponseOnEvent => {
                                        self._response_on_event(req, &cfg).await
                                    }
                                    Service::LinkCtrl => self._link_ctrl(req, &cfg).await,
                                    Service::NRC => {
                                        self.negative_service(
                                            Service::NRC.into(),
                                            Code::ServiceNotSupported,
                                        )
                                        .await;
                                        Ok(())
                                    }
                                } {
                                    self.process_uds_error(service, e).await;
                                }
                            }
                            Err(e) => {
                                rsutil::warn!(
                                    "{} error: {} when data: {} to request",
                                    LOG_TAG_SERVER,
                                    e,
                                    hex::encode(&data)
                                );
                                self.process_uds_error(service, e).await;
                            }
                        },
                        Err(_) => {
                            // can't parse service
                            self.negative_service(data[0], Code::ServiceNotSupported)
                                .await
                        }
                    },
                }
            }
        }
    }

    pub(crate) async fn negative_service(&self, service: u8, code: Code) {
        let data = vec![Service::NRC.into(), service, code.into()];
        if let Err(e) = self.isotp.transmit(AddressType::Physical, data).await {
            rsutil::error!(
                "{} can't transmit negative response, because of: {}",
                LOG_TAG_SERVER,
                e
            );
        }
    }

    pub(crate) async fn process_uds_error(&self, service: Service, e: Iso14229Error) {
        let code = match e {
            // Iso14229Error::InvalidParam(_) => {}
            // Iso14229Error::InvalidData(_) => {}
            Iso14229Error::InvalidDataLength { .. } => Code::IncorrectMessageLengthOrInvalidFormat,
            // Iso14229Error::DidNotSupported(_) => {}
            // Iso14229Error::InvalidDynamicallyDefinedDID(_) => {}
            // Iso14229Error::InvalidSessionData(_) => {}
            // Iso14229Error::ReservedError(_) => {}
            // Iso14229Error::SubFunctionError(_) => {}
            Iso14229Error::ServiceError(_) => Code::ConditionsNotCorrect,
            // Iso14229Error::OtherError(_) => {}
            // Iso14229Error::NotImplement => {}
            _ => Code::GeneralReject, // TODO
        };
        self.transmit_response(Response::new_negative(service, code), true)
            .await;
    }

    pub(crate) async fn transmit_response(&self, resp: Response, flag: bool) {
        let service = resp.service();
        let data: Vec<_> = resp.into();
        if let Err(e) = self.isotp.transmit(AddressType::Physical, data).await {
            rsutil::warn!("{} transmit error: {:?}", LOG_TAG_SERVER, e);
            if !flag {
                // resend negative response is no-need
                return;
            }

            if let Some(code) = match e {
                // IsoTpError::DeviceError => {}
                IsoTpError::EmptyPdu => Some(Code::IncorrectMessageLengthOrInvalidFormat),
                IsoTpError::InvalidPdu(_) => Some(Code::GeneralReject),
                IsoTpError::InvalidParam(_) => Some(Code::GeneralReject),
                IsoTpError::InvalidDataLength { .. } => {
                    Some(Code::IncorrectMessageLengthOrInvalidFormat)
                }
                IsoTpError::LengthOutOfRange(_) => Some(Code::RequestOutOfRange),
                IsoTpError::InvalidStMin(_) => Some(Code::GeneralReject),
                IsoTpError::InvalidSequence { .. } => Some(Code::WrongBlockSequenceCounter),
                IsoTpError::MixFramesError => Some(Code::GeneralReject),
                IsoTpError::Timeout { .. } => Some(Code::GeneralReject),
                IsoTpError::OverloadFlow => Some(Code::RequestOutOfRange),
                _ => None,
            } {
                let resp = Response::new_negative(service, code);
                Box::pin(self.transmit_response(resp, false)).await;
            }
        }
    }
}

#[async_trait::async_trait]
impl<D, C, F> uds_trait::UdsLayer for DoCanServer<D, C, F>
where
    D: CanDevice<Channel = C, Frame = F> + Clone + Send + 'static,
    C: Clone + Eq + Display + Send + Sync + 'static,
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
