use crate::{Config, DoCanError};
use bytes::{Bytes, BytesMut};
use iso14229_1::{
    request::{self, ClearDiagnosticInfo, IOCtrl},
    response::{self, Code, DTCFormatIdentifier, SessionTiming},
    utils::U24,
    CheckProgrammingDependencies, CommunicationCtrlType, CommunicationType, Configuration,
    DTCSettingType, DataFormatIdentifier, DataIdentifier, IOCtrlParameter, MemoryLocation,
    RoutineCtrlType, RoutineId,
};
use std::{collections::HashMap, sync::Arc};
use tokio::{
    fs::read,
    sync::{Mutex, MutexGuard},
};

#[derive(Clone)]
pub(crate) struct Context {
    pub(crate) config: Config,
    /// static did
    pub(crate) did_st: Arc<Mutex<HashMap<DataIdentifier, Bytes>>>,
    /// dynamic did
    pub(crate) did_dyn: Arc<Mutex<HashMap<DataIdentifier, Bytes>>>,
    pub(crate) sa_algo: Arc<Mutex<Option<uds_trait::SecurityAlgo<DoCanError>>>>,
    pub(crate) sa_ctx: Arc<Mutex<Option<(u8, Bytes)>>>,
    #[allow(dead_code)]
    pub(crate) memories: Arc<Mutex<HashMap<MemoryLocation, Bytes>>>,
    pub(crate) dtcs: Arc<Mutex<Vec<DtcRecord>>>,
    pub(crate) dtc_setting_enabled: Arc<Mutex<bool>>,
    pub(crate) active_timing: Arc<Mutex<SessionTiming>>,
    pub(crate) comm_ctrl_state: Arc<Mutex<CommunicationControlState>>,
    pub(crate) routine_results: Arc<Mutex<HashMap<u16, Vec<u8>>>>,
    pub(crate) transfer_meta: Arc<Mutex<Option<TransferMeta>>>,
    // pub(crate) session: SessionManager,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct DtcRecord {
    pub(crate) dtc: U24,
    pub(crate) status: u8,
    pub(crate) severity: u8,
    pub(crate) func_unit: u8,
    pub(crate) fault_counter: u8,
    pub(crate) permanent: bool,
    pub(crate) ext_data: Vec<(u8, Vec<u8>)>,
    pub(crate) mirror: bool,
    pub(crate) emissions_obd: bool,
    pub(crate) wwh_obd: Option<WwhObdMeta>,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) struct WwhObdMeta {
    pub(crate) func_gid: u8,
    pub(crate) fid: DTCFormatIdentifier,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) struct CommunicationControlState {
    pub(crate) ctrl_type: CommunicationCtrlType,
    pub(crate) comm_type: CommunicationType,
    pub(crate) node_id: Option<u16>,
}

impl Default for CommunicationControlState {
    fn default() -> Self {
        Self {
            ctrl_type: CommunicationCtrlType::EnableRxAndTx,
            comm_type: CommunicationType::NormalCommunicationMessages
                | CommunicationType::NetworkManagementCommunicationMessages,
            node_id: None,
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum TransferDirection {
    Download,
    Upload,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) struct TransferMeta {
    pub(crate) direction: TransferDirection,
    pub(crate) dfi: DataFormatIdentifier,
    pub(crate) mem_loc: MemoryLocation,
    pub(crate) max_num_of_block_len: u128,
    pub(crate) next_sequence: u8,
    pub(crate) transferred: u128,
}

impl Context {
    pub async fn new() -> Result<Self, DoCanError> {
        let reader = read("docan.server.yaml")
            .await
            .map_err(|e| DoCanError::OtherError(format!("{:?}", e)))?;
        let config = serde_yaml::from_slice::<Config>(reader.as_slice())
            .map_err(|e| DoCanError::OtherError(format!("{:?}", e)))?;
        let active_timing = config.timing;

        Ok(Self {
            config,
            did_st: Default::default(),
            did_dyn: Default::default(),
            sa_algo: Default::default(),
            sa_ctx: Default::default(),
            memories: Default::default(),
            dtcs: Default::default(),
            dtc_setting_enabled: Arc::new(Mutex::new(true)),
            active_timing: Arc::new(Mutex::new(active_timing)),
            comm_ctrl_state: Arc::new(Mutex::new(CommunicationControlState::default())),
            routine_results: Default::default(),
            transfer_meta: Default::default(),
            // session: Default::default(),
        })
    }

    pub async fn reset(&self) {
        self.did_dyn.lock().await.clear();
        let _ = self.sa_ctx.lock().await.take();
        self.dtcs.lock().await.clear();
        *self.dtc_setting_enabled.lock().await = true;
        *self.active_timing.lock().await = self.config.timing;
        *self.comm_ctrl_state.lock().await = CommunicationControlState::default();
        self.routine_results.lock().await.clear();
        let _ = self.transfer_meta.lock().await.take();
        // self.session.reset().await;
    }

    #[inline(always)]
    pub async fn get_active_timing(&self) -> SessionTiming {
        *self.active_timing.lock().await
    }

    #[inline(always)]
    pub fn get_cfg(&self) -> &Configuration {
        &self.config.cfg
    }

    pub async fn set_static_did<T: AsRef<[u8]>>(&mut self, did: &DataIdentifier, data: T) -> bool {
        match self.config.cfg.did.get(did) {
            Some(&len) => {
                let data = data.as_ref();
                if len != data.len() {
                    false
                } else {
                    self.did_st
                        .lock()
                        .await
                        .insert(*did, BytesMut::from(data).freeze());
                    true
                }
            }
            None => false,
        }
    }

    #[inline(always)]
    pub async fn get_static_did(&self, did: &DataIdentifier) -> Option<Bytes> {
        self.did_get_util(self.did_st.lock().await, &did)
    }

    #[inline(always)]
    pub fn get_static_did_sa_level(&self, did: &DataIdentifier) -> Option<u8> {
        self.config.did_sa_level.get(did).cloned()
    }

    #[allow(unused)]
    #[inline(always)]
    pub async fn set_dynamic_did<T: AsRef<[u8]>>(&mut self, did: &DataIdentifier, data: T) -> bool {
        match self.config.cfg.did.get(did) {
            Some(&len) => {
                let data = data.as_ref();
                if len != data.len() {
                    false
                } else {
                    self.did_dyn
                        .lock()
                        .await
                        .insert(*did, BytesMut::from(data).freeze());
                    true
                }
            }
            None => false,
        }
    }

    #[allow(unused)]
    #[inline(always)]
    pub async fn get_dynamic_did(&self, did: &DataIdentifier) -> Option<Bytes> {
        self.did_get_util(self.did_dyn.lock().await, &did)
    }

    #[inline(always)]
    pub fn get_security_salt(&self) -> &[u8] {
        &self.config.sa_salt
    }

    #[inline(always)]
    pub(crate) async fn set_security_algo(&self, alg: uds_trait::SecurityAlgo<DoCanError>) {
        let _ = self.sa_algo.lock().await.replace(alg);
    }

    #[inline(always)]
    pub async fn get_security_algo(&self) -> Option<uds_trait::SecurityAlgo<DoCanError>> {
        self.sa_algo.lock().await.clone()
    }

    #[inline(always)]
    fn did_get_util<'a>(
        &self,
        guard: MutexGuard<'a, HashMap<DataIdentifier, Bytes>>,
        did: &DataIdentifier,
    ) -> Option<Bytes> {
        match guard.get(did) {
            Some(data) => Some(data.clone()),
            None => {
                drop(guard);
                match self.config.cfg.did.get(did) {
                    Some(&len) => {
                        let mut data = Vec::with_capacity(len);
                        data.resize(len, 0);
                        Some(Bytes::from(data))
                    }
                    None => None,
                }
            }
        }
    }

    pub(crate) async fn dtc_records(&self) -> Vec<DtcRecord> {
        self.dtcs.lock().await.clone()
    }

    #[allow(dead_code)]
    pub(crate) async fn communication_ctrl_state(&self) -> CommunicationControlState {
        *self.comm_ctrl_state.lock().await
    }

    pub(crate) async fn set_dtc_setting(
        &self,
        r#type: DTCSettingType,
    ) -> Result<DTCSettingType, Code> {
        let enabled = match r#type {
            DTCSettingType::On => true,
            DTCSettingType::Off => false,
            _ => return Err(Code::SubFunctionNotSupported),
        };

        *self.dtc_setting_enabled.lock().await = enabled;
        Ok(r#type)
    }

    pub(crate) async fn communication_ctrl(
        &self,
        ctrl_type: CommunicationCtrlType,
        ctrl: &request::CommunicationCtrl,
    ) -> Result<(), Code> {
        match ctrl_type {
            CommunicationCtrlType::EnableRxAndTx
            | CommunicationCtrlType::EnableRxAndDisableTx
            | CommunicationCtrlType::DisableRxAndEnableTx
            | CommunicationCtrlType::DisableRxAndTx
            | CommunicationCtrlType::EnableRxAndDisableTxWithEnhancedAddressInformation
            | CommunicationCtrlType::EnableRxAndTxWithEnhancedAddressInformation => {
                *self.comm_ctrl_state.lock().await = CommunicationControlState {
                    ctrl_type,
                    comm_type: ctrl.comm_type,
                    node_id: ctrl.node_id.map(Into::into),
                };
                Ok(())
            }
            CommunicationCtrlType::Reserved(_)
            | CommunicationCtrlType::VehicleManufacturerSpecific(_)
            | CommunicationCtrlType::SystemSupplierSpecific(_) => {
                Err(Code::SubFunctionNotSupported)
            }
        }
    }

    pub(crate) async fn io_ctrl(&self, ctrl: &IOCtrl) -> Result<response::IOCtrl, Code> {
        if !ctrl.mask.is_empty() {
            return Err(Code::RequestOutOfRange);
        }

        if ctrl.option.param != IOCtrlParameter::ShortTermAdjustment {
            return Err(Code::RequestOutOfRange);
        }

        match self.config.cfg.did.get(&ctrl.did) {
            Some(&len) if len == ctrl.option.state.len() => {
                self.did_st.lock().await.insert(
                    ctrl.did,
                    BytesMut::from(ctrl.option.state.as_slice()).freeze(),
                );
            }
            _ => {
                return Err(Code::RequestOutOfRange);
            }
        }

        if self.get_static_did(&ctrl.did).await.is_none() {
            return Err(Code::RequestOutOfRange);
        }

        Ok(response::IOCtrl::new(
            ctrl.did,
            ctrl.option.param,
            ctrl.option.state.clone(),
        ))
    }

    pub(crate) async fn routine_ctrl(
        &self,
        r#type: RoutineCtrlType,
        routine_id: RoutineId,
        option_record: &[u8],
    ) -> Result<response::RoutineCtrl, Code> {
        if routine_id != CheckProgrammingDependencies {
            return Err(Code::RequestOutOfRange);
        }

        match r#type {
            RoutineCtrlType::StartRoutine => {
                if !option_record.is_empty() {
                    return Err(Code::RequestOutOfRange);
                }

                let result = vec![0x00];
                self.routine_results
                    .lock()
                    .await
                    .insert(routine_id.into(), result.clone());
                response::RoutineCtrl::new(routine_id, Some(0x00), result)
                    .map_err(|_| Code::GeneralReject)
            }
            RoutineCtrlType::RequestRoutineResults => {
                let result = self
                    .routine_results
                    .lock()
                    .await
                    .get(&u16::from(routine_id))
                    .cloned();
                match result {
                    Some(result) => response::RoutineCtrl::new(routine_id, Some(0x00), result)
                        .map_err(|_| Code::GeneralReject),
                    None => Err(Code::RequestSequenceError),
                }
            }
            RoutineCtrlType::StopRoutine => Err(Code::SubFunctionNotSupported),
        }
    }

    pub(crate) async fn request_download(
        &self,
        dfi: DataFormatIdentifier,
        mem_loc: MemoryLocation,
    ) -> Result<response::RequestDownload, Code> {
        let meta = self
            .start_transfer(TransferDirection::Download, dfi, mem_loc)
            .await?;
        response::RequestDownload::new(meta.max_num_of_block_len)
            .map_err(|_| Code::UploadDownloadNotAccepted)
    }

    pub(crate) async fn request_upload(
        &self,
        dfi: DataFormatIdentifier,
        mem_loc: MemoryLocation,
    ) -> Result<response::RequestUpload, Code> {
        let meta = self
            .start_transfer(TransferDirection::Upload, dfi, mem_loc)
            .await?;
        response::RequestUpload::new(meta.max_num_of_block_len)
            .map_err(|_| Code::UploadDownloadNotAccepted)
    }

    async fn start_transfer(
        &self,
        direction: TransferDirection,
        dfi: DataFormatIdentifier,
        mem_loc: MemoryLocation,
    ) -> Result<TransferMeta, Code> {
        if dfi.compression() != 0 || dfi.encryption() != 0 {
            return Err(Code::UploadDownloadNotAccepted);
        }

        let max_num_of_block_len = mem_loc.memory_size();
        if max_num_of_block_len == 0 {
            return Err(Code::RequestOutOfRange);
        }

        let meta = TransferMeta {
            direction,
            dfi,
            mem_loc,
            max_num_of_block_len,
            next_sequence: 1,
            transferred: 0,
        };
        self.transfer_meta.lock().await.replace(meta);
        Ok(meta)
    }

    pub(crate) async fn transfer_data(
        &self,
        sequence: u8,
        data: &[u8],
    ) -> Result<response::TransferData, Code> {
        let mut transfer_meta = self.transfer_meta.lock().await;
        let Some(mut meta) = transfer_meta.take() else {
            return Err(Code::RequestSequenceError);
        };

        if sequence != meta.next_sequence {
            transfer_meta.replace(meta);
            return Err(Code::WrongBlockSequenceCounter);
        }

        let remaining = meta.max_num_of_block_len.saturating_sub(meta.transferred);
        let resp_data = match meta.direction {
            TransferDirection::Download => {
                let chunk_len = u128::try_from(data.len()).map_err(|_| Code::RequestOutOfRange)?;
                if chunk_len == 0 || chunk_len > remaining {
                    transfer_meta.replace(meta);
                    return Err(Code::RequestOutOfRange);
                }

                let mut memories = self.memories.lock().await;
                let entry = memories.entry(meta.mem_loc).or_insert_with(Bytes::new);
                let mut buf = BytesMut::from(entry.as_ref());
                buf.extend_from_slice(data);
                *entry = buf.freeze();
                meta.transferred += chunk_len;
                Vec::new()
            }
            TransferDirection::Upload => {
                let memories = self.memories.lock().await;
                let Some(memory) = memories.get(&meta.mem_loc) else {
                    transfer_meta.replace(meta);
                    return Err(Code::RequestOutOfRange);
                };

                let memory_len =
                    u128::try_from(memory.len()).map_err(|_| Code::RequestOutOfRange)?;
                if memory_len < meta.max_num_of_block_len {
                    transfer_meta.replace(meta);
                    return Err(Code::RequestOutOfRange);
                }
                if !data.is_empty() || remaining == 0 {
                    transfer_meta.replace(meta);
                    return Err(Code::RequestSequenceError);
                }

                let start =
                    usize::try_from(meta.transferred).map_err(|_| Code::RequestOutOfRange)?;
                let end_u128 = meta.transferred + remaining;
                let end = usize::try_from(end_u128).map_err(|_| Code::RequestOutOfRange)?;
                let chunk = memory.slice(start..end.min(memory.len())).to_vec();
                if chunk.is_empty() {
                    transfer_meta.replace(meta);
                    return Err(Code::RequestOutOfRange);
                }

                meta.transferred +=
                    u128::try_from(chunk.len()).map_err(|_| Code::RequestOutOfRange)?;
                chunk
            }
        };

        meta.next_sequence = meta.next_sequence.wrapping_add(1);
        transfer_meta.replace(meta);
        Ok(response::TransferData {
            sequence,
            data: resp_data,
        })
    }

    pub(crate) async fn request_transfer_exit(
        &self,
        data: &[u8],
    ) -> Result<response::RequestTransferExit, Code> {
        let mut transfer_meta = self.transfer_meta.lock().await;
        let Some(meta) = transfer_meta.as_ref() else {
            return Err(Code::RequestSequenceError);
        };

        if meta.transferred != meta.max_num_of_block_len {
            return Err(Code::RequestSequenceError);
        }

        let _ = transfer_meta.take();
        Ok(response::RequestTransferExit {
            data: data.to_vec(),
        })
    }

    #[cfg(any(feature = "std2006", feature = "std2013"))]
    pub(crate) async fn access_timing_parameter(
        &self,
        r#type: iso14229_1::TimingParameterAccessType,
        data: &[u8],
    ) -> Result<response::AccessTimingParameter, Code> {
        use crate::constants::{P2_MAX, P2_STAR_MAX};
        match r#type {
            iso14229_1::TimingParameterAccessType::ReadCurrentlyActiveTimingParameters => {
                let timing = *self.active_timing.lock().await;
                Ok(response::AccessTimingParameter {
                    data: timing.into(),
                })
            }
            iso14229_1::TimingParameterAccessType::SetTimingParametersToDefaultValues => {
                if !data.is_empty() {
                    return Err(Code::IncorrectMessageLengthOrInvalidFormat);
                }
                *self.active_timing.lock().await = self.config.timing;
                Ok(response::AccessTimingParameter { data: vec![] })
            }
            iso14229_1::TimingParameterAccessType::SetTimingParametersToGivenValues => {
                if data.len() != 4 {
                    return Err(Code::IncorrectMessageLengthOrInvalidFormat);
                }

                let p2 = u16::from_be_bytes([data[0], data[1]]);
                let p2_star = u16::from_be_bytes([data[2], data[3]]);
                if p2 > P2_MAX || p2_star > P2_STAR_MAX {
                    return Err(Code::RequestOutOfRange);
                }

                *self.active_timing.lock().await = SessionTiming { p2, p2_star };
                Ok(response::AccessTimingParameter { data: vec![] })
            }
            iso14229_1::TimingParameterAccessType::ReadExtendedTimingParameterSet => {
                Err(Code::SubFunctionNotSupported)
            }
        }
    }

    pub(crate) async fn clear_diagnostic_info(
        &self,
        info: ClearDiagnosticInfo,
    ) -> Result<(), Code> {
        #[cfg(any(feature = "std2020"))]
        if info.memory_selection().is_some() {
            return Err(Code::RequestOutOfRange);
        }

        let group = info.group();
        if group == 0xFF_FF_FF {
            self.dtcs.lock().await.clear();
        } else {
            return Err(Code::RequestOutOfRange);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{CommunicationControlState, Context, DtcRecord, TransferDirection};
    use crate::server::Config;
    use bytes::Bytes;
    use iso14229_1::{
        request::{self, ClearDiagnosticInfo, IOCtrl},
        response,
        utils::U24,
        AddressAndLengthFormatIdentifier, CheckProgrammingDependencies, CommunicationCtrlType,
        CommunicationType, Configuration, DTCSettingType, DataFormatIdentifier, DataIdentifier,
        IOCtrlParameter, MemoryLocation, RoutineCtrlType, RoutineId,
    };
    use iso15765_2::can::Address;
    use rsutil::types::ByteOrder;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    impl Context {
        pub(crate) async fn replace_dtcs(&self, dtcs: Vec<DtcRecord>) {
            *self.dtcs.lock().await = dtcs;
        }

        pub(crate) async fn dtc_setting_enabled(&self) -> bool {
            *self.dtc_setting_enabled.lock().await
        }
    }

    fn test_context() -> Context {
        let did = DataIdentifier::from(0x4101);
        let mut cfg = Configuration::default();
        cfg.did.insert(did, 2);

        Context {
            config: Config {
                address: Address::default(),
                timing: Default::default(),
                extend_sa_level: 3,
                program_sa_level: 5,
                seed_len: 4,
                sa_salt: vec![1, 2, 3, 4],
                cfg,
                did_sa_level: Default::default(),
                byte_order: ByteOrder::default(),
            },
            did_st: Default::default(),
            did_dyn: Default::default(),
            sa_algo: Default::default(),
            sa_ctx: Default::default(),
            memories: Default::default(),
            dtcs: Default::default(),
            dtc_setting_enabled: Arc::new(Mutex::new(true)),
            active_timing: Arc::new(Mutex::new(Default::default())),
            comm_ctrl_state: Arc::new(Mutex::new(CommunicationControlState::default())),
            routine_results: Default::default(),
            transfer_meta: Default::default(),
            // session: Default::default(),
        }
    }

    fn sample_mem_loc(size: u32) -> MemoryLocation {
        MemoryLocation::new(
            AddressAndLengthFormatIdentifier::new(0x04, 0x04).unwrap(),
            0x0000_0001,
            size.into(),
        )
        .unwrap()
    }

    fn sample_dtc(dtc: u32) -> DtcRecord {
        DtcRecord {
            dtc: U24::new(dtc),
            status: 0x08,
            severity: 0x20,
            func_unit: 0x01,
            fault_counter: 3,
            permanent: true,
            ext_data: vec![(0x02, vec![0xAA, 0xBB])],
            mirror: false,
            emissions_obd: false,
            wwh_obd: None,
        }
    }

    #[tokio::test]
    async fn clear_diagnostic_info_clears_all_for_global_group() {
        let ctx = test_context();
        ctx.replace_dtcs(vec![sample_dtc(0x112233), sample_dtc(0x445566)])
            .await;

        #[cfg(any(feature = "std2020"))]
        let req = ClearDiagnosticInfo::new(U24::new(0xFF_FF_FF), None);
        #[cfg(any(feature = "std2006", feature = "std2013"))]
        let req = ClearDiagnosticInfo::new(U24::new(0xFF_FF_FF));

        ctx.clear_diagnostic_info(req).await.unwrap();
        assert!(ctx.dtc_records().await.is_empty());
    }

    #[tokio::test]
    async fn clear_diagnostic_info_rejects_non_global_group() {
        let ctx = test_context();

        #[cfg(any(feature = "std2020"))]
        let req = ClearDiagnosticInfo::new(U24::new(0x112233), None);
        #[cfg(any(feature = "std2006", feature = "std2013"))]
        let req = ClearDiagnosticInfo::new(U24::new(0x112233));

        let err = ctx.clear_diagnostic_info(req).await.unwrap_err();
        assert_eq!(err, response::Code::RequestOutOfRange);
    }

    #[cfg(any(feature = "std2020"))]
    #[tokio::test]
    async fn clear_diagnostic_info_rejects_memory_selection() {
        let ctx = test_context();
        let req = ClearDiagnosticInfo::new(U24::new(0xFF_FF_FF), Some(0x01));

        let err = ctx.clear_diagnostic_info(req).await.unwrap_err();
        assert_eq!(err, response::Code::RequestOutOfRange);
    }

    #[tokio::test]
    async fn ctrl_dtc_setting_toggles_enabled_state() {
        let ctx = test_context();
        assert!(ctx.dtc_setting_enabled().await);

        let setting = ctx.set_dtc_setting(DTCSettingType::Off).await.unwrap();
        assert_eq!(setting, DTCSettingType::Off);
        assert!(!ctx.dtc_setting_enabled().await);

        let setting = ctx.set_dtc_setting(DTCSettingType::On).await.unwrap();
        assert_eq!(setting, DTCSettingType::On);
        assert!(ctx.dtc_setting_enabled().await);
    }

    #[tokio::test]
    async fn ctrl_dtc_setting_rejects_vendor_specific_sub_function() {
        let ctx = test_context();
        let err = ctx
            .set_dtc_setting(DTCSettingType::VehicleManufacturerSpecific(0x40))
            .await
            .unwrap_err();

        assert_eq!(err, response::Code::SubFunctionNotSupported);
    }

    #[tokio::test]
    async fn communication_ctrl_records_real_state_for_standard_and_enhanced_modes() {
        let ctx = test_context();

        let base = request::CommunicationCtrl::new(
            CommunicationCtrlType::DisableRxAndTx,
            CommunicationType::NormalCommunicationMessages,
            None,
        )
        .unwrap();
        ctx.communication_ctrl(CommunicationCtrlType::DisableRxAndTx, &base)
            .await
            .unwrap();
        assert_eq!(
            ctx.communication_ctrl_state().await,
            CommunicationControlState {
                ctrl_type: CommunicationCtrlType::DisableRxAndTx,
                comm_type: CommunicationType::NormalCommunicationMessages,
                node_id: None,
            }
        );

        let enhanced = request::CommunicationCtrl::new(
            CommunicationCtrlType::EnableRxAndTxWithEnhancedAddressInformation,
            CommunicationType::NormalCommunicationMessages
                | CommunicationType::NetworkManagementCommunicationMessages,
            Some(request::NodeId::try_from(0x1234).unwrap()),
        )
        .unwrap();
        ctx.communication_ctrl(
            CommunicationCtrlType::EnableRxAndTxWithEnhancedAddressInformation,
            &enhanced,
        )
        .await
        .unwrap();
        assert_eq!(
            ctx.communication_ctrl_state().await,
            CommunicationControlState {
                ctrl_type: CommunicationCtrlType::EnableRxAndTxWithEnhancedAddressInformation,
                comm_type: CommunicationType::NormalCommunicationMessages
                    | CommunicationType::NetworkManagementCommunicationMessages,
                node_id: Some(0x1234),
            }
        );
    }

    #[tokio::test]
    async fn communication_ctrl_rejects_non_standard_subfunctions_and_resets_to_default() {
        let ctx = test_context();
        let ctrl = request::CommunicationCtrl::new(
            CommunicationCtrlType::EnableRxAndTx,
            CommunicationType::NormalCommunicationMessages,
            None,
        )
        .unwrap();

        let err = ctx
            .communication_ctrl(
                CommunicationCtrlType::VehicleManufacturerSpecific(0x40),
                &ctrl,
            )
            .await
            .unwrap_err();
        assert_eq!(err, response::Code::SubFunctionNotSupported);

        ctx.communication_ctrl(CommunicationCtrlType::DisableRxAndEnableTx, &ctrl)
            .await
            .unwrap();
        ctx.reset().await;
        assert_eq!(
            ctx.communication_ctrl_state().await,
            CommunicationControlState::default()
        );
    }

    #[tokio::test]
    async fn io_ctrl_short_term_adjustment_updates_did_state() {
        let ctx = test_context();
        let did = DataIdentifier::from(0x4101);

        let ctrl = IOCtrl::new(
            did,
            IOCtrlParameter::ShortTermAdjustment,
            vec![0x00, 0x40],
            vec![],
            &ctx.config.cfg,
        )
        .unwrap();

        let resp = ctx.io_ctrl(&ctrl).await.unwrap();
        assert_eq!(resp.did, did);
        assert_eq!(resp.status.param, IOCtrlParameter::ShortTermAdjustment);
        assert_eq!(resp.status.state, vec![0x00, 0x40]);
        assert_eq!(
            ctx.get_static_did(&did).await.unwrap().as_ref(),
            &[0x00, 0x40]
        );
    }

    #[tokio::test]
    async fn io_ctrl_rejects_control_enable_mask() {
        let ctx = test_context();
        let did = DataIdentifier::from(0x4101);

        let ctrl = IOCtrl::new(
            did,
            IOCtrlParameter::ShortTermAdjustment,
            vec![0x00, 0x40],
            vec![0xFF],
            &ctx.config.cfg,
        )
        .unwrap();

        let err = ctx.io_ctrl(&ctrl).await.unwrap_err();
        assert_eq!(err, response::Code::RequestOutOfRange);
    }

    #[tokio::test]
    async fn io_ctrl_rejects_non_short_term_adjustment() {
        let ctx = test_context();
        let did = DataIdentifier::from(0x4101);

        let ctrl = IOCtrl::new(
            did,
            IOCtrlParameter::ReturnControlToEcu,
            vec![],
            vec![],
            &ctx.config.cfg,
        )
        .unwrap();

        let err = ctx.io_ctrl(&ctrl).await.unwrap_err();
        assert_eq!(err, response::Code::RequestOutOfRange);
    }

    #[tokio::test]
    async fn routine_ctrl_start_then_request_results() {
        let ctx = test_context();

        let start = ctx
            .routine_ctrl(
                RoutineCtrlType::StartRoutine,
                CheckProgrammingDependencies,
                &[],
            )
            .await
            .unwrap();
        assert_eq!(start.routine_id, CheckProgrammingDependencies);
        assert_eq!(start.routine_info, Some(0x00));
        assert_eq!(start.routine_status, vec![0x00]);

        let results = ctx
            .routine_ctrl(
                RoutineCtrlType::RequestRoutineResults,
                CheckProgrammingDependencies,
                &[],
            )
            .await
            .unwrap();
        assert_eq!(results.routine_id, CheckProgrammingDependencies);
        assert_eq!(results.routine_info, Some(0x00));
        assert_eq!(results.routine_status, vec![0x00]);
    }

    #[tokio::test]
    async fn routine_ctrl_requires_start_before_results() {
        let ctx = test_context();

        let err = ctx
            .routine_ctrl(
                RoutineCtrlType::RequestRoutineResults,
                CheckProgrammingDependencies,
                &[],
            )
            .await
            .unwrap_err();
        assert_eq!(err, response::Code::RequestSequenceError);
    }

    #[tokio::test]
    async fn routine_ctrl_rejects_unsupported_subfunction_and_routine() {
        let ctx = test_context();

        let err = ctx
            .routine_ctrl(
                RoutineCtrlType::StopRoutine,
                CheckProgrammingDependencies,
                &[],
            )
            .await
            .unwrap_err();
        assert_eq!(err, response::Code::SubFunctionNotSupported);

        let err = ctx
            .routine_ctrl(RoutineCtrlType::StartRoutine, RoutineId(0xFF02), &[])
            .await
            .unwrap_err();
        assert_eq!(err, response::Code::RequestOutOfRange);
    }

    #[tokio::test]
    async fn routine_ctrl_reset_clears_stored_results() {
        let ctx = test_context();
        ctx.routine_ctrl(
            RoutineCtrlType::StartRoutine,
            CheckProgrammingDependencies,
            &[],
        )
        .await
        .unwrap();

        ctx.reset().await;

        let err = ctx
            .routine_ctrl(
                RoutineCtrlType::RequestRoutineResults,
                CheckProgrammingDependencies,
                &[],
            )
            .await
            .unwrap_err();
        assert_eq!(err, response::Code::RequestSequenceError);
    }

    #[tokio::test]
    async fn transfer_meta_records_download_and_upload() {
        let ctx = test_context();
        let dfi = DataFormatIdentifier::new(0x00, 0x00);
        let mem_loc = sample_mem_loc(0x40);

        let resp = ctx.request_download(dfi, mem_loc).await.unwrap();
        assert_eq!(resp.max_num_of_block_len, 0x40);
        let meta = ctx.transfer_meta.lock().await.unwrap();
        assert_eq!(meta.direction, TransferDirection::Download);
        assert_eq!(meta.dfi, dfi);
        assert_eq!(meta.mem_loc, mem_loc);
        assert_eq!(meta.next_sequence, 1);
        assert_eq!(meta.transferred, 0);
        let _ = meta;

        let resp = ctx.request_upload(dfi, mem_loc).await.unwrap();
        assert_eq!(resp.max_num_of_block_len, 0x40);
        let meta = ctx.transfer_meta.lock().await.unwrap();
        assert_eq!(meta.direction, TransferDirection::Upload);
        assert_eq!(meta.next_sequence, 1);
        assert_eq!(meta.transferred, 0);
    }

    #[tokio::test]
    async fn transfer_meta_rejects_non_default_dfi_and_zero_size() {
        let ctx = test_context();

        let err = ctx
            .request_download(DataFormatIdentifier::new(0x01, 0x01), sample_mem_loc(0x40))
            .await
            .unwrap_err();
        assert_eq!(err, response::Code::UploadDownloadNotAccepted);

        let zero_mem = MemoryLocation::new(
            AddressAndLengthFormatIdentifier::new(0x04, 0x04).unwrap(),
            0x0000_0001,
            0u128,
        );
        assert!(zero_mem.is_err());
    }

    #[tokio::test]
    async fn transfer_meta_reset_clears_active_transfer() {
        let ctx = test_context();
        ctx.request_download(DataFormatIdentifier::new(0x00, 0x00), sample_mem_loc(0x40))
            .await
            .unwrap();

        ctx.reset().await;

        assert!(ctx.transfer_meta.lock().await.is_none());
    }

    #[tokio::test]
    async fn transfer_data_download_writes_memory_and_advances_state() {
        let ctx = test_context();
        let mem_loc = sample_mem_loc(4);
        ctx.request_download(DataFormatIdentifier::new(0x00, 0x00), mem_loc)
            .await
            .unwrap();

        let resp = ctx.transfer_data(1, &[0x11, 0x22]).await.unwrap();
        assert_eq!(resp.sequence, 1);
        assert!(resp.data.is_empty());

        let resp = ctx.transfer_data(2, &[0x33, 0x44]).await.unwrap();
        assert_eq!(resp.sequence, 2);
        assert!(resp.data.is_empty());

        let stored = ctx.memories.lock().await.get(&mem_loc).cloned().unwrap();
        assert_eq!(stored, Bytes::from_static(&[0x11, 0x22, 0x33, 0x44]));
        let meta = ctx.transfer_meta.lock().await.unwrap();
        assert_eq!(meta.transferred, 4);
        assert_eq!(meta.next_sequence, 3);
    }

    #[tokio::test]
    async fn transfer_data_upload_reads_memory_and_advances_state() {
        let ctx = test_context();
        let mem_loc = sample_mem_loc(4);
        ctx.memories
            .lock()
            .await
            .insert(mem_loc, Bytes::from_static(&[0xAA, 0xBB, 0xCC, 0xDD]));
        ctx.request_upload(DataFormatIdentifier::new(0x00, 0x00), mem_loc)
            .await
            .unwrap();

        let resp = ctx.transfer_data(1, &[]).await.unwrap();
        assert_eq!(resp.sequence, 1);
        assert_eq!(resp.data, vec![0xAA, 0xBB, 0xCC, 0xDD]);

        let meta = ctx.transfer_meta.lock().await.unwrap();
        assert_eq!(meta.transferred, 4);
        assert_eq!(meta.next_sequence, 2);
    }

    #[tokio::test]
    async fn transfer_data_rejects_missing_transfer_wrong_sequence_and_invalid_direction_payload() {
        let ctx = test_context();
        let upload_mem = sample_mem_loc(2);

        let err = ctx.transfer_data(1, &[0x11]).await.unwrap_err();
        assert_eq!(err, response::Code::RequestSequenceError);

        ctx.request_download(DataFormatIdentifier::new(0x00, 0x00), sample_mem_loc(2))
            .await
            .unwrap();
        let err = ctx.transfer_data(2, &[0x11]).await.unwrap_err();
        assert_eq!(err, response::Code::WrongBlockSequenceCounter);

        ctx.memories
            .lock()
            .await
            .insert(upload_mem, Bytes::from_static(&[0x10, 0x20]));
        ctx.request_upload(DataFormatIdentifier::new(0x00, 0x00), upload_mem)
            .await
            .unwrap();
        let err = ctx.transfer_data(1, &[0x11]).await.unwrap_err();
        assert_eq!(err, response::Code::RequestSequenceError);
    }

    #[tokio::test]
    async fn request_transfer_exit_requires_completed_transfer_and_clears_state() {
        let ctx = test_context();
        let mem_loc = sample_mem_loc(2);
        ctx.request_download(DataFormatIdentifier::new(0x00, 0x00), mem_loc)
            .await
            .unwrap();

        let err = ctx.request_transfer_exit(&[0x99]).await.unwrap_err();
        assert_eq!(err, response::Code::RequestSequenceError);

        ctx.transfer_data(1, &[0x01, 0x02]).await.unwrap();
        let resp = ctx.request_transfer_exit(&[0x99]).await.unwrap();
        assert_eq!(resp.data, vec![0x99]);
        assert!(ctx.transfer_meta.lock().await.is_none());
    }

    #[cfg(any(feature = "std2006", feature = "std2013"))]
    #[tokio::test]
    async fn access_timing_parameter_reads_sets_and_resets_active_timing() {
        use iso14229_1::TimingParameterAccessType;

        let ctx = test_context();

        let read = ctx
            .access_timing_parameter(
                TimingParameterAccessType::ReadCurrentlyActiveTimingParameters,
                &[],
            )
            .await
            .unwrap();
        assert_eq!(read.data, Vec::<u8>::from(ctx.config.timing));

        let set = ctx
            .access_timing_parameter(
                TimingParameterAccessType::SetTimingParametersToGivenValues,
                &[0x00, 0x32, 0x00, 0x64],
            )
            .await
            .unwrap();
        assert!(set.data.is_empty());
        assert_eq!(
            ctx.get_active_timing().await,
            response::SessionTiming {
                p2: 50,
                p2_star: 100
            }
        );

        let reset = ctx
            .access_timing_parameter(
                TimingParameterAccessType::SetTimingParametersToDefaultValues,
                &[],
            )
            .await
            .unwrap();
        assert!(reset.data.is_empty());
        assert_eq!(ctx.get_active_timing().await, ctx.config.timing);
    }

    #[cfg(any(feature = "std2006", feature = "std2013"))]
    #[tokio::test]
    async fn access_timing_parameter_rejects_unsupported_subfunction_and_invalid_values() {
        use iso14229_1::TimingParameterAccessType;

        let ctx = test_context();

        let err = ctx
            .access_timing_parameter(
                TimingParameterAccessType::ReadExtendedTimingParameterSet,
                &[],
            )
            .await
            .unwrap_err();
        assert_eq!(err, response::Code::SubFunctionNotSupported);

        let err = ctx
            .access_timing_parameter(
                TimingParameterAccessType::SetTimingParametersToGivenValues,
                &[0x00, 0x33, 0x00, 0x64],
            )
            .await
            .unwrap_err();
        assert_eq!(err, response::Code::RequestOutOfRange);

        let err = ctx
            .access_timing_parameter(
                TimingParameterAccessType::SetTimingParametersToGivenValues,
                &[0x00, 0x32, 0x01],
            )
            .await
            .unwrap_err();
        assert_eq!(err, response::Code::IncorrectMessageLengthOrInvalidFormat);
    }
}
