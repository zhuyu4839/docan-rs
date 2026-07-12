/* - Diagnostic and communication management functional unit - */
#[cfg(any(feature = "std2006", feature = "std2013"))]
mod access_timing_parameter; // 0x83 ✅
#[cfg(any(feature = "std2020"))]
mod authentication; // 0x29 ✅
mod communication_ctrl; // 0x28 ✅
mod ctrl_dtc_setting; // 0x85 ✅
mod ecu_reset; // 0x11 ✅
mod link_ctrl; // 0x87 ✅
mod response_on_event; // 0x86 ❌
mod secured_data_trans; // 0x84 ❌
mod security_access; // 0x27 ✅
mod session_ctrl; // 0x10 ✅
mod tester_present; // 0x3E ✅

/* - Data transmission functional unit - */
mod dynamically_define_did; // 0x2C ❌
mod read_data_by_pid; // 0x2A ❌
mod read_did; // 0x22 ✅
mod read_mem_by_addr; // 0x23 ❌
mod read_scaling_did; // 0x24 ❌
mod write_did; // 0x2E ✅
mod write_mem_by_addr; // 0x3D ✅

/* - Stored data transmission functional unit - */
mod clear_diagnostic_info; // 0x14 ✅
mod read_dtc_info; // 0x19 ⭕

/* - InputOutput control functional unit - */
mod io_ctrl; // 0x2F ✅

/* - Remote activation of routine functional unit - */
mod routine_ctrl; // 0x31 ✅

/* - Upload download functional unit - */
mod request_download; // 0x34 ✅
#[cfg(any(feature = "std2013", feature = "std2020"))]
mod request_file_transfer; // 0x38 ❌
mod request_transfer_exit; // 0x37 ✅
mod request_upload; // 0x35 ✅
mod transfer_data; // 0x36 ✅

use crate::{constants::LOG_TAG_SERVER, DoCanError};
use iso14229_1::{request::Request, *};
use iso15765_2::IsoTp as _;
use rs_can::{CanDevice, CanFrame};
use std::{fmt::Display, sync::Arc};
use tokio::spawn;

#[async_trait::async_trait]
impl<D, C, F> uds_trait::UdsServer for super::DoCanServer<D, C, F>
where
    D: CanDevice<Channel = C, Frame = F> + Clone + Send + 'static,
    C: Clone + Eq + Display + Send + Sync + 'static,
    F: CanFrame<Channel = C> + Clone + Display + 'static,
{
    async fn service_forever(&mut self, interval_us: u64) {
        self.isotp.start(interval_us).await;
        let mut clone = self.clone();
        let session = self.session.clone();
        let handle = spawn(async move { session.work().await });
        self.handles.push(Arc::new(handle));
        let handle = spawn(async move { clone.server().await });
        self.handles.push(Arc::new(handle));
    }

    async fn service_stop(&mut self) {
        self.isotp.stop().await;
        for handle in &self.handles {
            handle.abort();
        }
        rsutil::info!("{} stopped", LOG_TAG_SERVER);
    }

    #[cfg(any(feature = "std2006", feature = "std2013"))]
    async fn access_timing_parameter(
        &self,
        req: Request,
        cfg: &Configuration,
    ) -> Result<(), Self::Error> {
        self._access_timing_parameter(req, cfg).await
    }

    async fn authentication(&self, req: Request, cfg: &Configuration) -> Result<(), Self::Error> {
        self._authentication(req, cfg)
            .await
            .map_err(DoCanError::Iso14229Error)
    }
    async fn communication_ctrl(
        &self,
        req: Request,
        cfg: &Configuration,
    ) -> Result<(), Self::Error> {
        self._communication_ctrl(req, cfg)
            .await
            .map_err(DoCanError::Iso14229Error)
    }
    async fn ctrl_dtc_setting(&self, req: Request, cfg: &Configuration) -> Result<(), Self::Error> {
        self._ctrl_dtc_setting(req, cfg)
            .await
            .map_err(DoCanError::Iso14229Error)
    }
    async fn ecu_reset(&self, req: Request, cfg: &Configuration) -> Result<(), Self::Error> {
        self._ecu_reset(req, cfg)
            .await
            .map_err(DoCanError::Iso14229Error)
    }
    async fn link_ctrl(&self, req: Request, cfg: &Configuration) -> Result<(), Self::Error> {
        self._link_ctrl(req, cfg)
            .await
            .map_err(DoCanError::Iso14229Error)
    }
    async fn response_on_event(
        &self,
        req: Request,
        cfg: &Configuration,
    ) -> Result<(), Self::Error> {
        self._response_on_event(req, cfg)
            .await
            .map_err(DoCanError::Iso14229Error)
    }
    async fn secured_data_trans(
        &self,
        req: Request,
        cfg: &Configuration,
    ) -> Result<(), Self::Error> {
        self._secured_data_trans(req, cfg)
            .await
            .map_err(DoCanError::Iso14229Error)
    }
    async fn security_access(&self, req: Request, cfg: &Configuration) -> Result<(), Self::Error> {
        self._security_access(req, cfg)
            .await
            .map_err(DoCanError::Iso14229Error)
    }
    async fn session_ctrl(
        &mut self,
        req: Request,
        cfg: &Configuration,
        data: Vec<u8>,
    ) -> Result<(), Self::Error> {
        self._session_ctrl(req, cfg, data)
            .await
            .map_err(DoCanError::Iso14229Error)
    }
    async fn tester_present(&self, req: Request, cfg: &Configuration) -> Result<(), Self::Error> {
        self._tester_present(req, cfg)
            .await
            .map_err(DoCanError::Iso14229Error)
    }
    async fn dynamically_define_did(
        &self,
        req: Request,
        cfg: &Configuration,
    ) -> Result<(), Self::Error> {
        self._dynamically_define_did(req, cfg)
            .await
            .map_err(DoCanError::Iso14229Error)
    }
    async fn read_data_by_pid(&self, req: Request, cfg: &Configuration) -> Result<(), Self::Error> {
        self._read_data_by_pid(req, cfg)
            .await
            .map_err(DoCanError::Iso14229Error)
    }
    async fn read_did(&self, req: Request, cfg: &Configuration) -> Result<(), Self::Error> {
        self._read_did(req, cfg)
            .await
            .map_err(DoCanError::Iso14229Error)
    }
    async fn read_mem_by_addr(&self, req: Request, cfg: &Configuration) -> Result<(), Self::Error> {
        self._read_mem_by_addr(req, cfg)
            .await
            .map_err(DoCanError::Iso14229Error)
    }
    async fn read_scaling_did(&self, req: Request, cfg: &Configuration) -> Result<(), Self::Error> {
        self._read_scaling_did(req, cfg)
            .await
            .map_err(DoCanError::Iso14229Error)
    }
    async fn write_did(&mut self, req: Request, cfg: &Configuration) -> Result<(), Self::Error> {
        self._write_did(req, cfg)
            .await
            .map_err(DoCanError::Iso14229Error)
    }
    async fn write_mem_by_addr(
        &self,
        req: Request,
        cfg: &Configuration,
    ) -> Result<(), Self::Error> {
        self._write_mem_by_addr(req, cfg)
            .await
            .map_err(DoCanError::Iso14229Error)
    }
    async fn clear_diagnostic_info(
        &self,
        req: Request,
        cfg: &Configuration,
    ) -> Result<(), Self::Error> {
        self._clear_diagnostic_info(req, cfg)
            .await
            .map_err(DoCanError::Iso14229Error)
    }
    async fn read_dtc_info(&self, req: Request, cfg: &Configuration) -> Result<(), Self::Error> {
        self._read_dtc_info(req, cfg)
            .await
            .map_err(DoCanError::Iso14229Error)
    }
    async fn io_ctrl(&self, req: Request, cfg: &Configuration) -> Result<(), Self::Error> {
        self._io_ctrl(req, cfg)
            .await
            .map_err(DoCanError::Iso14229Error)
    }
    async fn routine_ctrl(&self, req: Request, cfg: &Configuration) -> Result<(), Self::Error> {
        self._routine_ctrl(req, cfg)
            .await
            .map_err(DoCanError::Iso14229Error)
    }
    async fn request_download(&self, req: Request, cfg: &Configuration) -> Result<(), Self::Error> {
        self._request_download(req, cfg)
            .await
            .map_err(DoCanError::Iso14229Error)
    }
    #[cfg(any(feature = "std2013", feature = "std2020"))]
    async fn request_file_transfer(
        &self,
        req: Request,
        cfg: &Configuration,
    ) -> Result<(), Self::Error> {
        self._request_file_transfer(req, cfg)
            .await
            .map_err(DoCanError::Iso14229Error)
    }
    async fn request_transfer_exit(
        &self,
        req: Request,
        cfg: &Configuration,
    ) -> Result<(), Self::Error> {
        self._request_transfer_exit(req, cfg)
            .await
            .map_err(DoCanError::Iso14229Error)
    }
    async fn request_upload(&self, req: Request, cfg: &Configuration) -> Result<(), Self::Error> {
        self._request_upload(req, cfg)
            .await
            .map_err(DoCanError::Iso14229Error)
    }
    async fn transfer_data(&self, req: Request, cfg: &Configuration) -> Result<(), Self::Error> {
        self._transfer_data(req, cfg)
            .await
            .map_err(DoCanError::Iso14229Error)
    }
}
