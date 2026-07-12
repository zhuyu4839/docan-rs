/* - Diagnostic and communication management functional unit - */
#[cfg(any(feature = "std2006", feature = "std2013"))] // std2004
mod access_timing_parameter; // 0x83 ✅
#[cfg(any(feature = "std2020"))]
mod authentication; // 0x29 ✅
mod communication_ctrl; // 0x28 ✅
mod ctrl_dtc_setting; // 0x85 ✅
mod ecu_reset; // 0x11 ✅
mod link_ctrl; // 0x87 ✅
mod response_on_event; // 0x86 ✅
mod secured_data_trans; // 0x84 ✅
mod security_access; // 0x27 ✅
mod session_ctrl; // 0x10 ✅
mod tester_present; // 0x3E ✅

/* - Data transmission functional unit - */
mod dynamically_define_did; // 0x2C ✅
mod read_data_by_pid; // 0x2A ✅
mod read_did; // 0x22 ✅
mod read_mem_by_addr; // 0x23 ✅
mod read_scaling_did; // 0x24 ✅
mod write_did; // 0x2E ✅
mod write_mem_by_addr; // 0x3D ✅

/* - Stored data transmission functional unit - */
mod clear_diagnostic_info; // 0x14 ✅
mod read_dtc_info; // 0x19 ✅

/* - InputOutput control functional unit - */
mod io_ctrl; // 0x2F ✅

/* - Remote activation of routine functional unit - */
mod routine_ctrl; // 0x31 ✅

/* - Upload download functional unit - */
mod request_download; // 0x34 ✅
#[cfg(any(feature = "std2013", feature = "std2020"))]
mod request_file_transfer; // 0x38 ✅
mod request_transfer_exit; // 0x37 ✅
mod request_upload; // 0x35 ✅
mod transfer_data; // 0x36 ✅

use iso14229_1::{utils::U24, *};
use rs_can::{CanDevice, CanFrame};
use std::{fmt::Display, hash::Hash};

#[async_trait::async_trait]
impl<D, C, F> uds_trait::UdsClient for super::DoCanClient<D, C, F>
where
    D: CanDevice<Channel = C, Frame = F> + Clone + Send + 'static,
    C: Display + Clone + Hash + Eq + Send + Sync + 'static,
    F: CanFrame<Channel = C> + Clone + Display + 'static,
{
    async fn add_data_identifier(&self, did: DataIdentifier, length: usize) {
        self.context.add_did(did, length).await;
    }
    async fn remove_data_identifier(&self, did: DataIdentifier) {
        self.context.remove_did(&did).await;
    }

    #[cfg(any(feature = "std2006", feature = "std2013"))]
    async fn access_timing_parameter(
        &self,
        r#type: request::TimingParameterAccessType,
        parameter: Vec<u8>,
        suppress_positive: bool,
    ) -> Result<Option<response::AccessTimingParameter>, Self::Error> {
        self._access_timing_parameter(r#type, parameter, suppress_positive)
            .await
    }

    #[cfg(any(feature = "std2020"))]
    async fn authentication(
        &self,
        auth_task: iso14229_1::AuthenticationTask,
        data: request::Authentication,
    ) -> Result<response::Authentication, Self::Error> {
        self._authentication(auth_task, data).await
    }

    async fn communication_control(
        &self,
        ctrl_type: CommunicationCtrlType,
        comm_type: CommunicationType,
        node_id: Option<request::NodeId>,
        suppress_positive: bool,
        addr_type: iso15765_2::can::AddressType,
    ) -> Result<(), Self::Error> {
        self._communication_control(ctrl_type, comm_type, node_id, suppress_positive, addr_type)
            .await
    }

    async fn control_dtc_setting(
        &self,
        r#type: DTCSettingType,
        parameter: Vec<u8>,
        suppress_positive: bool,
    ) -> Result<(), Self::Error> {
        self._control_dtc_setting(r#type, parameter, suppress_positive)
            .await
    }

    async fn ecu_reset(
        &self,
        r#type: ECUResetType,
        suppress_positive: bool,
        addr_type: iso15765_2::can::AddressType,
    ) -> Result<(), Self::Error> {
        self._ecu_reset(r#type, suppress_positive, addr_type).await
    }

    async fn link_control(
        &self,
        r#type: LinkCtrlType,
        data: request::LinkCtrl,
        suppress_positive: bool,
    ) -> Result<(), Self::Error> {
        self._link_control(r#type, data, suppress_positive).await
    }

    async fn response_on_event(
        &self,
        data: request::ResponseOnEvent,
    ) -> Result<response::ResponseOnEvent, Self::Error> {
        self._response_on_event(data).await
    }

    async fn secured_data_transmit(
        &self,
        apar: AdministrativeParameter,
        signature: SignatureEncryptionCalculation,
        anti_replay_cnt: u16,
        service: u8,
        service_data: Vec<u8>,
        signature_data: Vec<u8>,
    ) -> Result<response::SecuredDataTrans, Self::Error> {
        self._secured_data_transmit(
            apar,
            signature,
            anti_replay_cnt,
            service,
            service_data,
            signature_data,
        )
        .await
    }

    async fn security_access(&self, level: u8, params: Vec<u8>) -> Result<Vec<u8>, Self::Error> {
        self._security_access(level, params).await
    }

    async fn unlock_security_access(
        &self,
        level: u8,
        params: Vec<u8>,
        salt: Vec<u8>,
    ) -> Result<(), Self::Error> {
        self._unlock_security_access(level, params, salt).await
    }

    async fn session_ctrl(
        &self,
        r#type: SessionType,
        suppress_positive: bool,
        addr_type: iso15765_2::can::AddressType,
    ) -> Result<(), Self::Error> {
        self._session_ctrl(r#type, suppress_positive, addr_type)
            .await
    }

    async fn tester_present(
        &self,
        r#type: TesterPresentType,
        suppress_positive: bool,
        addr_type: iso15765_2::can::AddressType,
    ) -> Result<(), Self::Error> {
        self._tester_present(r#type, suppress_positive, addr_type)
            .await
    }

    async fn dynamically_define_data_by_identifier(
        &self,
        r#type: DefinitionType,
        data: request::DynamicallyDefineDID,
        suppress_positive: bool,
    ) -> Result<Option<response::DynamicallyDefineDID>, Self::Error> {
        self._dynamically_define_data_by_identifier(r#type, data, suppress_positive)
            .await
    }

    async fn read_data_by_period_identifier(
        &self,
        mode: request::TransmissionMode,
        did: Vec<u8>,
    ) -> Result<response::ReadDataByPeriodId, Self::Error> {
        self._read_data_by_period_identifier(mode, did).await
    }

    async fn read_data_by_identifier(
        &self,
        did: DataIdentifier,
        others: Vec<DataIdentifier>,
    ) -> Result<response::ReadDID, Self::Error> {
        self._read_data_by_identifier(did, others).await
    }

    async fn read_memory_by_address(
        &self,
        mem_loc: MemoryLocation,
    ) -> Result<Vec<u8>, Self::Error> {
        self._read_memory_by_address(mem_loc).await
    }

    async fn read_scaling_data_by_identifier(
        &self,
        did: DataIdentifier,
    ) -> Result<response::ReadScalingDID, Self::Error> {
        self._read_scaling_data_by_identifier(did).await
    }

    async fn write_data_by_identifier(
        &self,
        did: DataIdentifier,
        data: Vec<u8>,
    ) -> Result<(), Self::Error> {
        self._write_data_by_identifier(did, data).await
    }

    async fn write_memory_by_address(
        &self,
        alfi: AddressAndLengthFormatIdentifier,
        mem_addr: u128,
        mem_size: u128,
        record: Vec<u8>,
    ) -> Result<response::WriteMemByAddr, Self::Error> {
        self._write_memory_by_address(alfi, mem_addr, mem_size, record)
            .await
    }

    async fn clear_dtc_info(
        &self,
        group: U24,
        mem_sel: Option<u8>,
        addr_type: iso15765_2::can::AddressType,
    ) -> Result<(), Self::Error> {
        self._clear_dtc_info(group, mem_sel, addr_type).await
    }

    async fn read_dtc_info(
        &self,
        r#type: DTCReportType,
        data: request::DTCInfo,
    ) -> Result<response::DTCInfo, Self::Error> {
        self._read_dtc_info(r#type, data).await
    }

    async fn io_control(
        &self,
        did: DataIdentifier,
        param: IOCtrlParameter,
        state: Vec<u8>,
        mask: Vec<u8>,
    ) -> Result<response::IOCtrl, Self::Error> {
        self._io_control(did, param, state, mask).await
    }

    async fn routine_control(
        &self,
        r#type: RoutineCtrlType,
        routine_id: u16,
        option_record: Vec<u8>,
    ) -> Result<response::RoutineCtrl, Self::Error> {
        self._routine_control(r#type, routine_id, option_record)
            .await
    }

    async fn request_download(
        &self,
        alfi: AddressAndLengthFormatIdentifier,
        mem_addr: u128,
        mem_size: u128,
        dfi: Option<DataFormatIdentifier>,
    ) -> Result<response::RequestDownload, Self::Error> {
        self._request_download(alfi, mem_addr, mem_size, dfi).await
    }

    #[cfg(any(feature = "std2013", feature = "std2020"))]
    async fn request_file_transfer(
        &self,
        operation: ModeOfOperation,
        data: request::RequestFileTransfer,
    ) -> Result<response::RequestFileTransfer, Self::Error> {
        self._request_file_transfer(operation, data).await
    }

    async fn request_transfer_exit(&self, parameter: Vec<u8>) -> Result<Vec<u8>, Self::Error> {
        self._request_transfer_exit(parameter).await
    }

    async fn request_upload(
        &self,
        alfi: AddressAndLengthFormatIdentifier,
        mem_addr: u128,
        mem_size: u128,
        dfi: Option<DataFormatIdentifier>,
    ) -> Result<response::RequestUpload, Self::Error> {
        self._request_upload(alfi, mem_addr, mem_size, dfi).await
    }

    async fn transfer_data(
        &self,
        sequence: u8,
        data: Vec<u8>,
    ) -> Result<response::TransferData, Self::Error> {
        self._transfer_data(sequence, data).await
    }
}
