//! response of Service 29

use crate::{constants::LOG_TAG_SERVER, server::DoCanServer};
use iso14229_1::{
    request::{self, Request},
    response::{self, AuthReturnValue, Code, Response},
    AuthenticationTask, Configuration, Iso14229Error,
};
use rs_can::{CanDevice, CanFrame};
use std::fmt::Display;

impl<D, C, F> DoCanServer<D, C, F>
where
    D: CanDevice<Channel = C, Frame = F> + Clone + Send + 'static,
    C: Clone + Eq + Display + Send + Sync + 'static,
    F: CanFrame<Channel = C> + Clone + Display + 'static,
{
    pub(crate) async fn _authentication(
        &self,
        req: Request,
        cfg: &Configuration,
    ) -> Result<(), Iso14229Error> {
        let service = req.service();
        let resp = match req.data::<request::Authentication>(cfg) {
            Ok(ctx) => match req.sub_function() {
                Some(sf) => {
                    if sf.is_suppress_positive() {
                        Response::new_negative(service, Code::SubFunctionNotSupported)
                    } else {
                        #[allow(unused)]
                        match sf.function::<AuthenticationTask>() {
                            Ok(task) => {
                                let data = match ctx {
                                    request::Authentication::DeAuthenticate => {
                                        response::Authentication::DeAuthenticate(
                                            AuthReturnValue::RequestAccepted
                                        )
                                    }
                                    request::Authentication::VerifyCertificateUnidirectional {
                                        config,
                                        certificate,
                                        challenge
                                    } => {
                                        response::Authentication::VerifyCertificateUnidirectional {
                                            value: AuthReturnValue::RequestAccepted,
                                            challenge: certificate,
                                            ephemeral_public_key: challenge,
                                        }
                                    }
                                    request::Authentication::VerifyCertificateBidirectional {
                                        config,
                                        challenge,
                                        certificate
                                    } => {
                                        response::Authentication::VerifyCertificateBidirectional {
                                            value: AuthReturnValue::RequestAccepted,
                                            challenge,
                                            certificate,
                                            proof_of_ownership: Default::default(),
                                            ephemeral_public_key: Default::default(),
                                        }
                                    }
                                    request::Authentication::ProofOfOwnership {
                                        proof_of_ownership,
                                        ephemeral_public_key,
                                    } => {
                                        response::Authentication::ProofOfOwnership {
                                            value: AuthReturnValue::RequestAccepted,
                                            session_keyinfo: ephemeral_public_key,
                                        }
                                    }
                                    request::Authentication::TransmitCertificate {
                                        cert_evaluation_id,
                                        certificate,
                                    } => {
                                        response::Authentication::TransmitCertificate(
                                            AuthReturnValue::RequestAccepted
                                        )
                                    }
                                    request::Authentication::RequestChallengeForAuthentication {
                                        config,
                                        algo_indicator,
                                    } => {
                                        response::Authentication::RequestChallengeForAuthentication {
                                            value: AuthReturnValue::RequestAccepted,
                                            algo_indicator,
                                            challenge: Default::default(),
                                            additional: Default::default(),
                                        }
                                    }
                                    request::Authentication::VerifyProofOfOwnershipUnidirectional {
                                        algo_indicator,
                                        proof_of_ownership,
                                        challenge,
                                        additional,
                                    } => {
                                        response::Authentication::VerifyProofOfOwnershipUnidirectional {
                                            value: AuthReturnValue::RequestAccepted,
                                            algo_indicator,
                                            session_keyinfo: Default::default(),
                                        }
                                    }
                                    request::Authentication::VerifyProofOfOwnershipBidirectional {
                                        algo_indicator,
                                        proof_of_ownership,
                                        challenge,
                                        additional,
                                    } => {
                                        response::Authentication::VerifyProofOfOwnershipBidirectional {
                                            value: AuthReturnValue::RequestAccepted,
                                            algo_indicator,
                                            proof_of_ownership,
                                            session_keyinfo: Default::default(),
                                        }
                                    }
                                    request::Authentication::AuthenticationConfiguration => {
                                        response::Authentication::AuthenticationConfiguration(
                                            AuthReturnValue::RequestAccepted,
                                        )
                                    }
                                };

                                Response::new::<Vec<_>>(service, Some(sf.into()), data.into(), cfg)?
                            }
                            Err(e) => {
                                rsutil::warn!(
                                    "{} can't parse sub-function on service: {}, because of: {}",
                                    LOG_TAG_SERVER,
                                    service,
                                    e
                                );
                                Response::new_negative(
                                    service,
                                    Code::IncorrectMessageLengthOrInvalidFormat,
                                )
                            }
                        }
                    }
                }
                None => {
                    rsutil::warn!(
                        "{} can't get sub-function on service: {}",
                        LOG_TAG_SERVER,
                        service
                    );
                    Response::new_negative(service, Code::GeneralReject)
                }
            },
            Err(e) => {
                rsutil::warn!("{} Failed to parse request data: {:?}", LOG_TAG_SERVER, e);
                Response::new_negative(service, Code::GeneralReject)
            }
        };

        self.transmit_response(resp, true).await;

        Ok(())
    }
}
