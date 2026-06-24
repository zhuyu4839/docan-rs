//! response of Service 19

use crate::server::{context::DtcRecord, DoCanServer};
use iso14229_1::{
    request::{self, Request},
    response::{self, Code, Response},
    Configuration, Iso14229Error,
};
use rs_can::{CanDevice, CanFrame};
use std::fmt::Display;

fn availability_mask(records: &[DtcRecord]) -> u8 {
    records.iter().fold(0, |mask, record| mask | record.status)
}

fn status_filtered(records: &[DtcRecord], mask: u8) -> Vec<DtcRecord> {
    records
        .iter()
        .filter(|record| record.status & mask != 0)
        .cloned()
        .collect()
}

fn status_records(records: &[DtcRecord]) -> Vec<response::DTCAndStatusRecord> {
    records
        .iter()
        .map(|record| response::DTCAndStatusRecord {
            dtc: record.dtc,
            status: record.status,
        })
        .collect()
}

fn first_matching(records: &[DtcRecord], mask: u8) -> Option<response::DTCAndStatusRecord> {
    records.iter().find_map(|record| {
        (record.status & mask != 0).then_some(response::DTCAndStatusRecord {
            dtc: record.dtc,
            status: record.status,
        })
    })
}

fn last_matching(records: &[DtcRecord], mask: u8) -> Option<response::DTCAndStatusRecord> {
    records.iter().rev().find_map(|record| {
        (record.status & mask != 0).then_some(response::DTCAndStatusRecord {
            dtc: record.dtc,
            status: record.status,
        })
    })
}

fn validated_ext_data_records(
    record: &DtcRecord,
    extra_num: u8,
    cfg: &Configuration,
) -> Result<Vec<response::DTCExtDataRecord>, Code> {
    let iter = record.ext_data.iter().filter(|(number, _)| {
        if extra_num == 0x00 {
            true
        } else {
            *number == extra_num
        }
    });

    iter.map(|(number, data)| match cfg.dtc.get(number) {
        Some(expected_len) if *expected_len == data.len() => Ok(response::DTCExtDataRecord {
            number: *number,
            data: data.clone(),
        }),
        _ => Err(Code::RequestOutOfRange),
    })
    .collect()
}

#[cfg(any(feature = "std2013", feature = "std2020"))]
fn validated_ext_data_payload(
    record: &DtcRecord,
    extra_num: u8,
    cfg: &Configuration,
) -> Result<Option<Vec<u8>>, Code> {
    let expected_len = cfg
        .dtc
        .get(&extra_num)
        .copied()
        .ok_or(Code::RequestOutOfRange)?;
    let mut matches = record
        .ext_data
        .iter()
        .filter(|(number, _)| *number == extra_num);

    let payload = match matches.next() {
        Some((_, data)) if data.len() == expected_len => Some(data.clone()),
        Some(_) => return Err(Code::RequestOutOfRange),
        None => None,
    };

    if matches.next().is_some() {
        return Err(Code::RequestOutOfRange);
    }

    Ok(payload)
}

#[cfg(any(feature = "std2013", feature = "std2020"))]
fn validated_wwh_fid(records: &[DtcRecord]) -> Result<response::DTCFormatIdentifier, Code> {
    let mut fids = records
        .iter()
        .filter_map(|record| record.wwh_obd.map(|meta| meta.fid));
    let Some(fid) = fids.next() else {
        return Err(Code::RequestOutOfRange);
    };

    match fid {
        response::DTCFormatIdentifier::SAE_J1939_73_DTCFormat
        | response::DTCFormatIdentifier::SAE_J2012_DA_DTCFormat_04 => {}
        _ => return Err(Code::RequestOutOfRange),
    }

    if fids.any(|other| other != fid) {
        return Err(Code::RequestOutOfRange);
    }

    Ok(fid)
}

fn build_read_dtc_response(
    req: request::DTCInfo,
    records: &[DtcRecord],
    cfg: &Configuration,
) -> Result<response::DTCInfo, Code> {
    let avl_mask = availability_mask(records);

    match req {
        request::DTCInfo::ReportNumberOfDTCByStatusMask(mask) => {
            // 0x01
            let filtered = status_filtered(records, mask);
            Ok(response::DTCInfo::ReportNumberOfDTCByStatusMask {
                avl_mask,
                fid: response::DTCFormatIdentifier::ISO_14229_1_DTCFormat,
                count: filtered.len() as u16,
            })
        }
        request::DTCInfo::ReportDTCByStatusMask(mask) => {
            let filtered = status_filtered(records, mask);
            Ok(response::DTCInfo::ReportDTCByStatusMask {
                avl_mask,
                records: status_records(&filtered),
            })
        }
        // request::DTCInfo::ReportDTCSnapshotIdentification => {
        //     todo!()
        // }
        // request::DTCInfo::ReportDTCSnapshotRecordByDTCNumber {
        //     mask_record: _,
        //     record_num: _,
        // } => {
        //     todo!()
        // }
        // #[cfg(feature = "std2006")]
        // request::DTCInfo::ReportDTCSnapshotRecordByRecordNumber { record_num: _ } => {
        //     todo!()
        // }
        // #[cfg(any(feature = "std2013", feature = "std2020"))]
        // request::DTCInfo::ReportDTCStoredDataByRecordNumber { stored_num: _ } => {
        //     todo!()
        // }
        request::DTCInfo::ReportDTCExtDataRecordByDTCNumber {
            mask_record,
            extra_num,
        } => {
            let record = records
                .iter()
                .find(|record| record.dtc == mask_record)
                .ok_or(Code::RequestOutOfRange)?;

            let ext_records = validated_ext_data_records(record, extra_num, cfg)?;

            Ok(response::DTCInfo::ReportDTCExtDataRecordByDTCNumber {
                status_record: response::DTCAndStatusRecord {
                    dtc: record.dtc,
                    status: record.status,
                },
                records: ext_records,
            })
        }
        request::DTCInfo::ReportNumberOfDTCBySeverityMaskRecord {
            // 0x07
            severity_mask,
            status_mask,
        } => {
            let filtered: Vec<_> = records
                .iter()
                .filter(|record| {
                    record.status & status_mask != 0 && record.severity & severity_mask != 0
                })
                .cloned()
                .collect();

            Ok(response::DTCInfo::ReportNumberOfDTCBySeverityMaskRecord {
                avl_mask,
                fid: response::DTCFormatIdentifier::ISO_14229_1_DTCFormat,
                count: filtered.len() as u16,
            })
        }
        request::DTCInfo::ReportDTCBySeverityMaskRecord {
            severity_mask,
            status_mask,
        } => {
            let mut filtered = records.iter().filter(|record| {
                record.status & status_mask != 0 && record.severity & severity_mask != 0
            });

            let first = filtered.next().ok_or(Code::RequestOutOfRange)?;
            let record = response::DTCAndSeverityRecord1 {
                severity: first.severity,
                func_unit: first.func_unit,
                dtc: first.dtc,
                status: first.status,
            };
            let others = filtered
                .map(|record| response::DTCAndSeverityRecord1 {
                    severity: record.severity,
                    func_unit: record.func_unit,
                    dtc: record.dtc,
                    status: record.status,
                })
                .collect();

            Ok(response::DTCInfo::ReportDTCBySeverityMaskRecord {
                avl_mask,
                record,
                others,
            })
        }
        request::DTCInfo::ReportSeverityInformationOfDTC { mask_record } => {
            let records = records
                .iter()
                .filter(|record| record.dtc == mask_record)
                .map(|record| response::DTCAndSeverityRecord1 {
                    severity: record.severity,
                    func_unit: record.func_unit,
                    dtc: record.dtc,
                    status: record.status,
                })
                .collect();

            Ok(response::DTCInfo::ReportSeverityInformationOfDTC { avl_mask, records })
        }
        request::DTCInfo::ReportSupportedDTC => {
            if records.is_empty() {
                return Err(Code::RequestOutOfRange);
            }

            Ok(response::DTCInfo::ReportSupportedDTC {
                avl_mask,
                records: status_records(records),
            })
        }
        request::DTCInfo::ReportFirstTestFailedDTC => first_matching(records, 0x01)
            .map(|record| response::DTCInfo::ReportFirstTestFailedDTC {
                avl_mask,
                record: Some(record),
            })
            .ok_or(Code::RequestOutOfRange),
        request::DTCInfo::ReportFirstConfirmedDTC => first_matching(records, 0x08)
            .map(|record| response::DTCInfo::ReportFirstConfirmedDTC {
                avl_mask,
                record: Some(record),
            })
            .ok_or(Code::RequestOutOfRange),
        request::DTCInfo::ReportMostRecentTestFailedDTC => last_matching(records, 0x01)
            .map(|record| response::DTCInfo::ReportMostRecentTestFailedDTC {
                avl_mask,
                record: Some(record),
            })
            .ok_or(Code::RequestOutOfRange),
        request::DTCInfo::ReportMostRecentConfirmedDTC => last_matching(records, 0x08)
            .map(|record| response::DTCInfo::ReportMostRecentConfirmedDTC {
                avl_mask,
                record: Some(record),
            })
            .ok_or(Code::RequestOutOfRange),
        #[cfg(any(feature = "std2006", feature = "std2013"))]
        request::DTCInfo::ReportMirrorMemoryDTCByStatusMask(mask) => {
            let mirror_records = records
                .iter()
                .filter(|record| record.mirror)
                .cloned()
                .collect::<Vec<_>>();
            let filtered = status_filtered(&mirror_records, mask);
            Ok(response::DTCInfo::ReportMirrorMemoryDTCByStatusMask {
                avl_mask: availability_mask(&mirror_records),
                records: status_records(&filtered),
            })
        }
        #[cfg(any(feature = "std2006", feature = "std2013"))]
        request::DTCInfo::ReportMirrorMemoryDTCExtDataRecordByDTCNumber {
            mask_record,
            extra_num,
        } => {
            let mut matches = records
                .iter()
                .filter(|record| record.mirror && record.dtc == mask_record);
            let record = matches.next().ok_or(Code::RequestOutOfRange)?;
            if matches.next().is_some() {
                return Err(Code::RequestOutOfRange);
            }

            let ext_records = validated_ext_data_records(record, extra_num, cfg)?;
            Ok(
                response::DTCInfo::ReportMirrorMemoryDTCExtDataRecordByDTCNumber {
                    status_record: response::DTCAndStatusRecord {
                        dtc: record.dtc,
                        status: record.status,
                    },
                    records: ext_records,
                },
            )
        }
        #[cfg(any(feature = "std2006", feature = "std2013"))]
        request::DTCInfo::ReportNumberOfMirrorMemoryDTCByStatusMask(mask) => {
            let mirror_records = records
                .iter()
                .filter(|record| record.mirror)
                .cloned()
                .collect::<Vec<_>>();
            let filtered = status_filtered(&mirror_records, mask);
            Ok(
                response::DTCInfo::ReportNumberOfMirrorMemoryDTCByStatusMask {
                    avl_mask: availability_mask(&mirror_records),
                    fid: response::DTCFormatIdentifier::ISO_14229_1_DTCFormat,
                    count: filtered.len() as u16,
                },
            )
        }
        #[cfg(any(feature = "std2006", feature = "std2013"))]
        request::DTCInfo::ReportNumberOfEmissionsOBDDTCByStatusMask(mask) => {
            let emissions_records = records
                .iter()
                .filter(|record| record.emissions_obd)
                .cloned()
                .collect::<Vec<_>>();
            let filtered = status_filtered(&emissions_records, mask);
            Ok(
                response::DTCInfo::ReportNumberOfEmissionsOBDDTCByStatusMask {
                    avl_mask: availability_mask(&emissions_records),
                    fid: response::DTCFormatIdentifier::ISO_14229_1_DTCFormat,
                    count: filtered.len() as u16,
                },
            )
        }
        #[cfg(any(feature = "std2006", feature = "std2013"))]
        request::DTCInfo::ReportEmissionsOBDDTCByStatusMask(mask) => {
            let emissions_records = records
                .iter()
                .filter(|record| record.emissions_obd)
                .cloned()
                .collect::<Vec<_>>();
            let filtered = status_filtered(&emissions_records, mask);
            Ok(response::DTCInfo::ReportEmissionsOBDDTCByStatusMask {
                avl_mask: availability_mask(&emissions_records),
                records: status_records(&filtered),
            })
        }
        request::DTCInfo::ReportDTCFaultDetectionCounter => {
            if records.is_empty() {
                return Err(Code::RequestOutOfRange);
            }

            let records = records
                .iter()
                .map(|record| response::DTCFaultDetectionCounterRecord {
                    dtc: record.dtc,
                    counter: record.fault_counter,
                })
                .collect();

            Ok(response::DTCInfo::ReportDTCFaultDetectionCounter { records })
        }
        request::DTCInfo::ReportDTCWithPermanentStatus => {
            let records: Vec<_> = records
                .iter()
                .filter(|record| record.permanent)
                .map(|record| response::DTCAndStatusRecord {
                    dtc: record.dtc,
                    status: record.status,
                })
                .collect();

            if records.is_empty() {
                return Err(Code::RequestOutOfRange);
            }

            Ok(response::DTCInfo::ReportDTCWithPermanentStatus { avl_mask, records })
        }
        #[cfg(any(feature = "std2013", feature = "std2020"))]
        request::DTCInfo::ReportDTCExtDataRecordByRecordNumber { extra_num } => {
            if extra_num == 0x00 {
                return Err(Code::RequestOutOfRange);
            }

            let records = records
                .iter()
                .filter_map(|record| {
                    validated_ext_data_payload(record, extra_num, cfg)
                        .transpose()
                        .map(|data| {
                            data.map(|data| response::DTCExtDataRecordByRecordNumber {
                                status_record: response::DTCAndStatusRecord {
                                    dtc: record.dtc,
                                    status: record.status,
                                },
                                data,
                            })
                        })
                })
                .collect::<Result<Vec<_>, _>>()?;

            Ok(response::DTCInfo::ReportDTCExtDataRecordByRecordNumber {
                number: extra_num,
                records,
            })
        }
        // #[cfg(any(feature = "std2013", feature = "std2020"))]
        // request::DTCInfo::ReportUserDefMemoryDTCByStatusMask {
        //     status_mask: _,
        //     mem_selection: _,
        // } => {
        //     todo!()
        // }
        // #[cfg(any(feature = "std2013", feature = "std2020"))]
        // request::DTCInfo::ReportUserDefMemoryDTCSnapshotRecordByDTCNumber {
        //     mask_record: _,
        //     record_num: _,
        //     mem_selection: _,
        // } => {
        //     todo!()
        // }
        // #[cfg(any(feature = "std2013", feature = "std2020"))]
        // request::DTCInfo::ReportUserDefMemoryDTCExtDataRecordByDTCNumber {
        //     mask_record: _,
        //     extra_num: _,
        //     mem_selection: _,
        // } => {
        //     todo!()
        // }
        #[cfg(any(feature = "std2020"))]
        request::DTCInfo::ReportSupportedDTCExtDataRecord { extra_num } => {
            let expected_len = match cfg.dtc.get(&extra_num).copied() {
                Some(expected_len) => expected_len,
                None => {
                    return Ok(response::DTCInfo::ReportSupportedDTCExtDataRecord {
                        avl_mask,
                        number: None,
                        records: vec![],
                    })
                }
            };

            let records = records
                .iter()
                .filter_map(|record| {
                    let matches = record
                        .ext_data
                        .iter()
                        .filter(|(number, _)| *number == extra_num)
                        .collect::<Vec<_>>();

                    match matches.as_slice() {
                        [] => Some(Ok(None)),
                        [(_, data)] if data.len() == expected_len => {
                            Some(Ok(Some(response::DTCAndStatusRecord {
                                dtc: record.dtc,
                                status: record.status,
                            })))
                        }
                        [(_, _)] => Some(Err(Code::RequestOutOfRange)),
                        _ => Some(Err(Code::RequestOutOfRange)),
                    }
                })
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .flatten()
                .collect::<Vec<_>>();

            Ok(response::DTCInfo::ReportSupportedDTCExtDataRecord {
                avl_mask,
                number: (!records.is_empty()).then_some(extra_num),
                records,
            })
        }
        #[cfg(any(feature = "std2013", feature = "std2020"))]
        request::DTCInfo::ReportWWHOBDDTCByMaskRecord {
            func_gid,
            status_mask,
            severity_mask,
        } => {
            if func_gid == 0xFF {
                return Err(Code::RequestOutOfRange);
            }

            let domain_records = records
                .iter()
                .filter(|record| record.wwh_obd.map(|meta| meta.func_gid) == Some(func_gid))
                .cloned()
                .collect::<Vec<_>>();
            let fid = validated_wwh_fid(&domain_records)?;
            let filtered = domain_records
                .iter()
                .filter(|record| {
                    record.status & status_mask != 0 && record.severity & severity_mask != 0
                })
                .map(|record| response::DTCAndSeverityRecord {
                    severity: record.severity,
                    dtc: record.dtc,
                    status: record.status,
                })
                .collect();

            Ok(response::DTCInfo::ReportWWHOBDDTCByMaskRecord {
                func_gid,
                status_avl_mask: availability_mask(&domain_records),
                severity_avl_mask: domain_records
                    .iter()
                    .fold(0, |mask, record| mask | record.severity),
                fid,
                records: filtered,
            })
        }
        #[cfg(any(feature = "std2013", feature = "std2020"))]
        request::DTCInfo::ReportWWHOBDDTCWithPermanentStatus { func_gid } => {
            if func_gid == 0xFF {
                return Err(Code::RequestOutOfRange);
            }

            let domain_records = records
                .iter()
                .filter(|record| record.wwh_obd.map(|meta| meta.func_gid) == Some(func_gid))
                .cloned()
                .collect::<Vec<_>>();
            let fid = validated_wwh_fid(&domain_records)?;
            let permanent_records = domain_records
                .iter()
                .filter(|record| record.permanent)
                .map(|record| response::DTCAndStatusRecord {
                    dtc: record.dtc,
                    status: record.status,
                })
                .collect();

            Ok(response::DTCInfo::ReportWWHOBDDTCWithPermanentStatus {
                func_gid,
                status_avl_mask: availability_mask(&domain_records),
                fid,
                records: permanent_records,
            })
        }
        // #[cfg(any(feature = "std2020"))]
        // request::DTCInfo::ReportDTCInformationByDTCReadinessGroupIdentifier {
        //     func_gid: _,
        //     readiness_gid: _,
        // } => {
        //     todo!()
        // }
        _ => Err(Code::SubFunctionNotSupported),
    }
}

impl<D, C, F> DoCanServer<D, C, F>
where
    D: CanDevice<Channel = C, Frame = F> + Clone + Send + 'static,
    C: Clone + Eq + Display + Send + Sync + 'static,
    F: CanFrame<Channel = C> + Clone + Display + 'static,
{
    pub(crate) async fn _read_dtc_info(
        &self,
        req: Request,
        cfg: &Configuration,
    ) -> Result<(), Iso14229Error> {
        let service = req.service();

        let resp = match req.data::<request::DTCInfo>(cfg) {
            Ok(ctx) => match req.sub_function() {
                Some(sf) => {
                    match build_read_dtc_response(ctx, &self.context.dtc_records().await, cfg) {
                        Ok(data) => {
                            if sf.is_suppress_positive() {
                                return Ok(());
                            }
                            Response::new(service, Some(u8::from(sf)), Vec::<u8>::from(data), cfg)?
                        }
                        Err(code) => Response::new_negative(service, code),
                    }
                }
                None => {
                    Response::new_negative(service, Code::IncorrectMessageLengthOrInvalidFormat)
                }
            },
            Err(_) => Response::new_negative(service, Code::IncorrectMessageLengthOrInvalidFormat),
        };

        self.transmit_response(resp, true).await;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{build_read_dtc_response, DtcRecord};
    use crate::server::context::Context;
    use iso14229_1::{request, response, response::Code, utils::U24, Configuration};

    fn sample_record(dtc: u32, status: u8) -> DtcRecord {
        DtcRecord {
            dtc: U24::new(dtc),
            status,
            severity: 0x20,
            func_unit: 0x01,
            fault_counter: 2,
            permanent: true,
            ext_data: vec![(0x02, vec![0xAA, 0xBB])],
            mirror: false,
            emissions_obd: false,
            wwh_obd: None,
        }
    }

    #[tokio::test]
    async fn read_clear_read_dtc_flow() {
        let ctx = Context::new().await.unwrap();
        ctx.replace_dtcs(vec![
            sample_record(0x112233, 0x08),
            sample_record(0x445566, 0x40),
        ])
        .await;

        let before = build_read_dtc_response(
            request::DTCInfo::ReportNumberOfDTCByStatusMask(0xFF),
            &ctx.dtc_records().await,
            ctx.get_cfg(),
        )
        .unwrap();

        match before {
            response::DTCInfo::ReportNumberOfDTCByStatusMask { count, .. } => {
                assert_eq!(count, 2);
            }
            _ => panic!("unexpected response variant"),
        }

        #[cfg(any(feature = "std2020"))]
        let invalid_clear = request::ClearDiagnosticInfo::new(U24::new(0x112233), None);
        #[cfg(any(feature = "std2006", feature = "std2013"))]
        let invalid_clear = request::ClearDiagnosticInfo::new(U24::new(0x112233));

        let invalid_err = ctx.clear_diagnostic_info(invalid_clear).await.unwrap_err();
        assert_eq!(invalid_err, Code::RequestOutOfRange);

        let after_invalid = build_read_dtc_response(
            request::DTCInfo::ReportNumberOfDTCByStatusMask(0xFF),
            &ctx.dtc_records().await,
            ctx.get_cfg(),
        )
        .unwrap();

        match after_invalid {
            response::DTCInfo::ReportNumberOfDTCByStatusMask { count, .. } => {
                assert_eq!(count, 2);
            }
            _ => panic!("unexpected response variant"),
        }

        #[cfg(any(feature = "std2020"))]
        let clear_all = request::ClearDiagnosticInfo::new(U24::new(0xFF_FF_FF), None);
        #[cfg(any(feature = "std2006", feature = "std2013"))]
        let clear_all = request::ClearDiagnosticInfo::new(U24::new(0xFF_FF_FF));

        ctx.clear_diagnostic_info(clear_all).await.unwrap();

        let after_clear = build_read_dtc_response(
            request::DTCInfo::ReportNumberOfDTCByStatusMask(0xFF),
            &ctx.dtc_records().await,
            ctx.get_cfg(),
        )
        .unwrap();

        match after_clear {
            response::DTCInfo::ReportNumberOfDTCByStatusMask { count, .. } => {
                assert_eq!(count, 0);
            }
            _ => panic!("unexpected response variant"),
        }
    }

    #[test]
    fn number_by_status_mask_counts_matching_records() {
        let records = vec![sample_record(0x112233, 0x08), sample_record(0x445566, 0x01)];
        let resp = build_read_dtc_response(
            request::DTCInfo::ReportNumberOfDTCByStatusMask(0x08),
            &records,
            &Default::default(),
        )
        .unwrap();

        match resp {
            response::DTCInfo::ReportNumberOfDTCByStatusMask { count, .. } => {
                assert_eq!(count, 1)
            }
            _ => panic!("unexpected response variant"),
        }
    }

    #[test]
    fn dtc_by_status_mask_returns_filtered_records() {
        let records = vec![sample_record(0x112233, 0x08), sample_record(0x445566, 0x01)];
        let resp = build_read_dtc_response(
            request::DTCInfo::ReportDTCByStatusMask(0x01),
            &records,
            &Default::default(),
        )
        .unwrap();

        match resp {
            response::DTCInfo::ReportDTCByStatusMask { records, .. } => {
                assert_eq!(records.len(), 1);
                assert_eq!(records[0].dtc, U24::new(0x445566));
            }
            _ => panic!("unexpected response variant"),
        }
    }

    #[test]
    fn ext_data_record_by_dtc_number_returns_matching_record_data() {
        let mut cfg = Configuration::default();
        cfg.dtc.insert(0x02, 2);
        let records = vec![sample_record(0x112233, 0x08)];
        let resp = build_read_dtc_response(
            request::DTCInfo::ReportDTCExtDataRecordByDTCNumber {
                mask_record: U24::new(0x112233),
                extra_num: 0x02,
            },
            &records,
            &cfg,
        )
        .unwrap();

        match resp {
            response::DTCInfo::ReportDTCExtDataRecordByDTCNumber { records, .. } => {
                assert_eq!(records.len(), 1);
                assert_eq!(records[0].number, 0x02);
                assert_eq!(records[0].data, vec![0xAA, 0xBB]);
            }
            _ => panic!("unexpected response variant"),
        }
    }

    #[test]
    fn supported_dtc_rejects_empty_records() {
        let err = build_read_dtc_response(
            request::DTCInfo::ReportSupportedDTC,
            &[],
            &Default::default(),
        )
        .unwrap_err();

        assert_eq!(err, Code::RequestOutOfRange);
    }

    #[test]
    fn first_confirmed_dtc_rejects_when_no_confirmed_record_exists() {
        let records = vec![sample_record(0x112233, 0x01)];
        let err = build_read_dtc_response(
            request::DTCInfo::ReportFirstConfirmedDTC,
            &records,
            &Default::default(),
        )
        .unwrap_err();

        assert_eq!(err, Code::RequestOutOfRange);
    }

    #[test]
    fn fault_detection_counter_rejects_empty_records() {
        let err = build_read_dtc_response(
            request::DTCInfo::ReportDTCFaultDetectionCounter,
            &[],
            &Default::default(),
        )
        .unwrap_err();

        assert_eq!(err, Code::RequestOutOfRange);
    }

    #[test]
    fn ext_data_record_rejects_unconfigured_record_length() {
        let records = vec![sample_record(0x112233, 0x08)];
        let err = build_read_dtc_response(
            request::DTCInfo::ReportDTCExtDataRecordByDTCNumber {
                mask_record: U24::new(0x112233),
                extra_num: 0x02,
            },
            &records,
            &Default::default(),
        )
        .unwrap_err();

        assert_eq!(err, Code::RequestOutOfRange);
    }

    #[cfg(any(feature = "std2006", feature = "std2013"))]
    #[test]
    fn mirror_and_emissions_list_reports_allow_empty_filtered_results() {
        let records = vec![DtcRecord {
            dtc: U24::new(0x112233),
            status: 0x08,
            severity: 0x20,
            func_unit: 0x01,
            fault_counter: 2,
            permanent: true,
            ext_data: vec![(0x02, vec![0xAA, 0xBB])],
            mirror: true,
            emissions_obd: true,
            wwh_obd: None,
        }];

        let mirror_resp = build_read_dtc_response(
            request::DTCInfo::ReportMirrorMemoryDTCByStatusMask(0x01),
            &records,
            &Default::default(),
        )
        .unwrap();
        match mirror_resp {
            response::DTCInfo::ReportMirrorMemoryDTCByStatusMask { avl_mask, records } => {
                assert_eq!(avl_mask, 0x08);
                assert!(records.is_empty());
            }
            _ => panic!("unexpected response variant"),
        }

        let emissions_resp = build_read_dtc_response(
            request::DTCInfo::ReportEmissionsOBDDTCByStatusMask(0x01),
            &records,
            &Default::default(),
        )
        .unwrap();
        match emissions_resp {
            response::DTCInfo::ReportEmissionsOBDDTCByStatusMask { avl_mask, records } => {
                assert_eq!(avl_mask, 0x08);
                assert!(records.is_empty());
            }
            _ => panic!("unexpected response variant"),
        }
    }

    #[cfg(any(feature = "std2013", feature = "std2020"))]
    #[test]
    fn ext_data_record_by_record_number_returns_matching_records() {
        let mut cfg = Configuration::default();
        cfg.dtc.insert(0x02, 2);

        let records = vec![
            sample_record(0x112233, 0x08),
            DtcRecord {
                dtc: U24::new(0x445566),
                status: 0x40,
                severity: 0x10,
                func_unit: 0x02,
                fault_counter: 1,
                permanent: false,
                ext_data: vec![(0x02, vec![0xCC, 0xDD])],
                mirror: false,
                emissions_obd: false,
                wwh_obd: None,
            },
        ];

        let resp = build_read_dtc_response(
            request::DTCInfo::ReportDTCExtDataRecordByRecordNumber { extra_num: 0x02 },
            &records,
            &cfg,
        )
        .unwrap();

        match resp {
            response::DTCInfo::ReportDTCExtDataRecordByRecordNumber { number, records } => {
                assert_eq!(number, 0x02);
                assert_eq!(records.len(), 2);
                assert_eq!(records[0].status_record.dtc, U24::new(0x112233));
                assert_eq!(records[0].data, vec![0xAA, 0xBB]);
                assert_eq!(records[1].status_record.dtc, U24::new(0x445566));
                assert_eq!(records[1].data, vec![0xCC, 0xDD]);
            }
            _ => panic!("unexpected response variant"),
        }
    }

    #[cfg(any(feature = "std2013", feature = "std2020"))]
    #[test]
    fn ext_data_record_by_record_number_rejects_zero_record_number() {
        let mut cfg = Configuration::default();
        cfg.dtc.insert(0x02, 2);

        let records = vec![sample_record(0x112233, 0x08)];
        let err = build_read_dtc_response(
            request::DTCInfo::ReportDTCExtDataRecordByRecordNumber { extra_num: 0x00 },
            &records,
            &cfg,
        )
        .unwrap_err();

        assert_eq!(err, Code::RequestOutOfRange);
    }

    #[cfg(any(feature = "std2013", feature = "std2020"))]
    #[test]
    fn ext_data_record_by_record_number_returns_empty_when_no_record_matches() {
        let mut cfg = Configuration::default();
        cfg.dtc.insert(0x04, 4);

        let records = vec![sample_record(0x112233, 0x08)];
        let resp = build_read_dtc_response(
            request::DTCInfo::ReportDTCExtDataRecordByRecordNumber { extra_num: 0x04 },
            &records,
            &cfg,
        )
        .unwrap();

        match resp {
            response::DTCInfo::ReportDTCExtDataRecordByRecordNumber { number, records } => {
                assert_eq!(number, 0x04);
                assert!(records.is_empty());
            }
            _ => panic!("unexpected response variant"),
        }
    }

    #[cfg(any(feature = "std2013", feature = "std2020"))]
    #[test]
    fn ext_data_record_by_record_number_rejects_unconfigured_number() {
        let records = vec![sample_record(0x112233, 0x08)];
        let err = build_read_dtc_response(
            request::DTCInfo::ReportDTCExtDataRecordByRecordNumber { extra_num: 0x02 },
            &records,
            &Default::default(),
        )
        .unwrap_err();

        assert_eq!(err, Code::RequestOutOfRange);
    }

    #[cfg(any(feature = "std2020"))]
    #[test]
    fn supported_ext_data_record_returns_matching_dtcs() {
        let mut cfg = Configuration::default();
        cfg.dtc.insert(0x02, 2);

        let records = vec![
            sample_record(0x112233, 0x08),
            DtcRecord {
                dtc: U24::new(0x445566),
                status: 0x40,
                severity: 0x10,
                func_unit: 0x02,
                fault_counter: 1,
                permanent: false,
                ext_data: vec![(0x04, vec![0x01, 0x02, 0x03, 0x04])],
                mirror: false,
                emissions_obd: false,
                wwh_obd: None,
            },
        ];

        let resp = build_read_dtc_response(
            request::DTCInfo::ReportSupportedDTCExtDataRecord { extra_num: 0x02 },
            &records,
            &cfg,
        )
        .unwrap();

        match resp {
            response::DTCInfo::ReportSupportedDTCExtDataRecord {
                avl_mask,
                number,
                records,
            } => {
                assert_eq!(avl_mask, 0x48);
                assert_eq!(number, Some(0x02));
                assert_eq!(records.len(), 1);
                assert_eq!(records[0].dtc, U24::new(0x112233));
            }
            _ => panic!("unexpected response variant"),
        }
    }

    #[cfg(any(feature = "std2020"))]
    #[test]
    fn supported_ext_data_record_returns_empty_when_unavailable() {
        let records = vec![sample_record(0x112233, 0x08)];
        let resp = build_read_dtc_response(
            request::DTCInfo::ReportSupportedDTCExtDataRecord { extra_num: 0x04 },
            &records,
            &Default::default(),
        )
        .unwrap();

        match resp {
            response::DTCInfo::ReportSupportedDTCExtDataRecord {
                avl_mask,
                number,
                records,
            } => {
                assert_eq!(avl_mask, 0x08);
                assert_eq!(number, None);
                assert!(records.is_empty());
            }
            _ => panic!("unexpected response variant"),
        }
    }
}
