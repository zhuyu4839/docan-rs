//! response of Service 38

use crate::server::DoCanServer;
use iso14229_1::{
    request::Request,
    response::{Code, Response},
    Configuration, Iso14229Error,
};
use rs_can::{CanDevice, CanFrame};
use std::fmt::Display;

impl<D, C, F> DoCanServer<D, C, F>
where
    D: CanDevice<Channel = C, Frame = F> + Clone + Send + 'static,
    C: Clone + Eq + Display + Send + Sync + 'static,
    F: CanFrame<Channel = C> + Clone + Display + 'static,
{
    pub(crate) async fn _request_file_transfer(
        &self,
        req: Request,
        _cfg: &Configuration,
    ) -> Result<(), Iso14229Error> {
        let service = req.service();

        let resp = if self.session.get_session_type().await == Default::default() {
            Response::new_negative(service, Code::ServiceNotSupportedInActiveSession)
        } else {
            Response::new_negative(service, Code::ServiceNotSupported)
        };

        self.transmit_response(resp, true).await;

        Ok(())
    }
}
