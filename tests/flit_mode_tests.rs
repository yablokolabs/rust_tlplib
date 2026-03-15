//! Flit Mode Tests (PCIe 6.x)
//!
//! Scope: parser tests for TLP byte streams as they appear inside a PCIe 6.x FLIT.
//! These are NOT full 256-byte FLIT containers — no DLP, CRC or FEC bytes.
//!
//! # Tier structure
//!
//! | Tier | Status | Unlock condition |
//! |------|--------|-----------------|
//! | 0 | ✅ passes today | N/A — permanent stub regression guard |
//! | 1 | `#[ignore]` | `FlitDW0` struct + `flit_dw0_from_bytes()` |
//! | 2 | `#[ignore]` | `FlitTlpType` enum + header-size table |
//! | 3 | `#[ignore]` | OHC parser + `TlpError::MissingMandatoryOhc` |
//! | 4 | `#[ignore]` | `FlitStreamWalker` / stream iterator |
//! | 5 | `#[ignore]` | `TlpPacket::new_flit()` fully wired |
//!
//! For non-flit tests see `tests/non_flit_tests.rs`.
//! For API surface tests see `tests/api_tests.rs`.
//! Design rationale: `docs/flit_mode_test_plan.md`.

use rtlp_lib::*;

// ============================================================================
// FM_* test vectors — from docs/flit_mode_tlp_examples.md
//
// DW0 flit-mode encoding:
//   Byte 0 = Type[7:0]   (flat 8-bit type code, NOT non-flit fmt+type)
//   Byte 1 = TC[2:0] | OHC[4:0]
//   Byte 2 = TS[2:0] | Attr[2:0] | Length[9:8]
//   Byte 3 = Length[7:0]
// ============================================================================

/// Flit-mode NOP. Smallest possible header-base object (1 DW, no payload).
pub const FM_NOP: [u8; 4] = [
    0x00, 0x00, 0x00, 0x00,
];

/// Minimal 32-bit Memory Read Request. Length=1 DW, no OHC, no payload.
pub const FM_MRD32_MIN: [u8; 12] = [
    0x03, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
];

/// 32-bit Memory Read Request with OHC-A1 carrying PASID=0x12345, fdwbe=0xF, ldwbe=0x0.
pub const FM_MRD32_A1_PASID: [u8; 16] = [
    0x03, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x01, 0x23, 0x45, 0x0F,
];

/// Minimal 32-bit Memory Write Request. Length=1 DW, no OHC, payload=0xDEADBEEF.
pub const FM_MWR32_MIN: [u8; 16] = [
    0x40, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0xDE, 0xAD, 0xBE, 0xEF,
];

/// 32-bit Memory Write Request with OHC-A1. fdwbe=0x3 (partial-byte write).
pub const FM_MWR32_PARTIAL_A1: [u8; 20] = [
    0x40, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x03,
    0xAA, 0xBB, 0xCC, 0xDD,
];

/// I/O Write Request with mandatory OHC-A2. fdwbe=0xF.
pub const FM_IOWR_A2: [u8; 20] = [
    0x42, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x0F,
    0x10, 0x20, 0x30, 0x40,
];

/// Type0 Configuration Write Request with mandatory OHC-A3. fdwbe=0xF.
pub const FM_CFGWR0_A3: [u8; 20] = [
    0x44, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x0F,
    0x44, 0x33, 0x22, 0x11,
];

/// Minimal UIO Memory Read Request (PCIe 6.1+ UIO). 4 DW base header, Length=2 DW, no payload.
pub const FM_UIOMRD64_MIN: [u8; 16] = [
    0x22, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
];

/// Minimal UIO Memory Write Request (PCIe 6.1+ UIO). 4 DW base header, 2 DW payload.
pub const FM_UIOMWR64_MIN: [u8; 24] = [
    0x61, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x11, 0x22, 0x33, 0x44,
    0x55, 0x66, 0x77, 0x88,
];

/// Message routed to RC, no data.
pub const FM_MSG_TO_RC: [u8; 12] = [
    0x30, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
];

/// Message with data, routed to RC.
pub const FM_MSGD_TO_RC: [u8; 16] = [
    0x70, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0xAA, 0x55, 0xAA, 0x55,
];

/// 32-bit FetchAdd AtomicOp Request. Operand = 0x01000000.
pub const FM_FETCHADD32: [u8; 16] = [
    0x4C, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00,
];

/// 32-bit Compare-and-Swap AtomicOp Request. Compare=0x11111111, Swap=0x22222222.
pub const FM_CAS32: [u8; 20] = [
    0x4E, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x11, 0x11, 0x11, 0x11,
    0x22, 0x22, 0x22, 0x22,
];

/// 32-bit Deferrable Memory Write Request.
pub const FM_DMWR32: [u8; 16] = [
    0x5B, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0xC0, 0xFF, 0xEE, 0x00,
];

/// Packed stream fragment: NOP + MRd32 + MWr32 + UIOMRd64 back-to-back.
pub const FM_STREAM_FRAGMENT_0: [u8; 48] = [
    // NOP (4 bytes, offset 0)
    0x00, 0x00, 0x00, 0x00,
    // MRd32 (12 bytes, offset 4)
    0x03, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    // MWr32 (16 bytes, offset 16)
    0x40, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0xDE, 0xAD, 0xBE, 0xEF,
    // UIOMRd64 (16 bytes, offset 32)
    0x22, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
];

/// Local TLP Prefix token (Appendix A — not a standalone transaction).
pub const FM_LOCAL_PREFIX_ONLY: [u8; 4] = [
    0x8D, 0x00, 0x00, 0x00,
];

// ============================================================================
// Tier 0 — Current stub behavior
//
// These tests PASS TODAY and act as permanent regression guards.
// They verify that TlpMode::Flit correctly returns NotImplemented until
// the flit parser is implemented.
// ============================================================================

#[test]
fn flit_packet_new_returns_not_implemented() {
    let bytes = FM_MRD32_MIN.to_vec();
    assert_eq!(
        TlpPacket::new(bytes, TlpMode::Flit).err().unwrap(),
        TlpError::NotImplemented
    );
}

#[test]
fn flit_header_new_returns_not_implemented() {
    let bytes = FM_MRD32_MIN.to_vec();
    assert_eq!(
        TlpPacketHeader::new(bytes, TlpMode::Flit).err().unwrap(),
        TlpError::NotImplemented
    );
}

#[test]
fn flit_byte_vectors_have_correct_sizes() {
    // Compile-time size sanity check — no parser required.
    assert_eq!(FM_NOP.len(),                 4);
    assert_eq!(FM_MRD32_MIN.len(),          12);
    assert_eq!(FM_MRD32_A1_PASID.len(),     16);
    assert_eq!(FM_MWR32_MIN.len(),          16);
    assert_eq!(FM_MWR32_PARTIAL_A1.len(),   20);
    assert_eq!(FM_IOWR_A2.len(),            20);
    assert_eq!(FM_CFGWR0_A3.len(),          20);
    assert_eq!(FM_UIOMRD64_MIN.len(),       16);
    assert_eq!(FM_UIOMWR64_MIN.len(),       24);
    assert_eq!(FM_MSG_TO_RC.len(),          12);
    assert_eq!(FM_MSGD_TO_RC.len(),         16);
    assert_eq!(FM_FETCHADD32.len(),         16);
    assert_eq!(FM_CAS32.len(),              20);
    assert_eq!(FM_DMWR32.len(),             16);
    assert_eq!(FM_STREAM_FRAGMENT_0.len(),  48);
    assert_eq!(FM_LOCAL_PREFIX_ONLY.len(),   4);
}

#[test]
fn flit_dw0_type_bytes_are_correct() {
    // Verify type code (byte 0) for each vector without any parser.
    assert_eq!(FM_NOP[0],               0x00, "FM_NOP type");
    assert_eq!(FM_MRD32_MIN[0],         0x03, "FM_MRD32_MIN type");
    assert_eq!(FM_MRD32_A1_PASID[0],    0x03, "FM_MRD32_A1_PASID type");
    assert_eq!(FM_MWR32_MIN[0],         0x40, "FM_MWR32_MIN type");
    assert_eq!(FM_MWR32_PARTIAL_A1[0],  0x40, "FM_MWR32_PARTIAL_A1 type");
    assert_eq!(FM_IOWR_A2[0],           0x42, "FM_IOWR_A2 type");
    assert_eq!(FM_CFGWR0_A3[0],         0x44, "FM_CFGWR0_A3 type");
    assert_eq!(FM_UIOMRD64_MIN[0],      0x22, "FM_UIOMRD64_MIN type");
    assert_eq!(FM_UIOMWR64_MIN[0],      0x61, "FM_UIOMWR64_MIN type");
    assert_eq!(FM_MSG_TO_RC[0],         0x30, "FM_MSG_TO_RC type");
    assert_eq!(FM_MSGD_TO_RC[0],        0x70, "FM_MSGD_TO_RC type");
    assert_eq!(FM_FETCHADD32[0],        0x4C, "FM_FETCHADD32 type");
    assert_eq!(FM_CAS32[0],             0x4E, "FM_CAS32 type");
    assert_eq!(FM_DMWR32[0],            0x5B, "FM_DMWR32 type");
    assert_eq!(FM_LOCAL_PREFIX_ONLY[0], 0x8D, "FM_LOCAL_PREFIX_ONLY type");
}

#[test]
fn flit_dw0_ohc_bytes_are_correct() {
    // Verify OHC presence flag (byte 1, bits[4:0]) for vectors with OHC.
    let ohc = |b: u8| b & 0x1F; // lower 5 bits = OHC field

    // No OHC
    assert_eq!(ohc(FM_NOP[1]),              0x00, "FM_NOP ohc");
    assert_eq!(ohc(FM_MRD32_MIN[1]),        0x00, "FM_MRD32_MIN ohc");
    assert_eq!(ohc(FM_MWR32_MIN[1]),        0x00, "FM_MWR32_MIN ohc");
    // OHC-A1 present (bit 0 set)
    assert_eq!(ohc(FM_MRD32_A1_PASID[1]),   0x01, "FM_MRD32_A1_PASID ohc-A1");
    assert_eq!(ohc(FM_MWR32_PARTIAL_A1[1]), 0x01, "FM_MWR32_PARTIAL_A1 ohc-A1");
    // OHC-A2/A3 present (bit 0 set via OHC-A presence)
    assert_eq!(ohc(FM_IOWR_A2[1]),          0x01, "FM_IOWR_A2 ohc-A2");
    assert_eq!(ohc(FM_CFGWR0_A3[1]),        0x01, "FM_CFGWR0_A3 ohc-A3");
}

// ============================================================================
// Tier 1 — Flit DW0 field extraction
//
// #[ignore] — pending: FlitDW0 struct and flit_dw0_from_bytes() in src/lib.rs
//
// Unlock: add `pub fn flit_dw0_from_bytes(b: &[u8]) -> Result<FlitDW0, TlpError>`
//         and `pub struct FlitDW0 { tlp_type, tc, ohc, ts, attr, length }`
// ============================================================================

#[test]
#[ignore = "pending: FlitDW0 struct not yet implemented (Tier 1)"]
fn flit_t1_nop_dw0_fields() {
    todo!("FlitDW0::from_dw0(FM_NOP) → type=Nop, tc=0, ohc=0, length=0");
}

#[test]
#[ignore = "pending: FlitDW0 struct not yet implemented (Tier 1)"]
fn flit_t1_mrd32_dw0_fields() {
    todo!("FlitDW0::from_dw0(FM_MRD32_MIN) → type=MemRead32, tc=0, ohc=0, length=1");
}

#[test]
#[ignore = "pending: FlitDW0 struct not yet implemented (Tier 1)"]
fn flit_t1_mrd32_a1_dw0_ohc_present() {
    todo!("FlitDW0::from_dw0(FM_MRD32_A1_PASID) → ohc=0x01 (OHC-A1 bit set)");
}

#[test]
#[ignore = "pending: FlitDW0 struct not yet implemented (Tier 1)"]
fn flit_t1_mwr32_dw0_fields() {
    todo!("FlitDW0::from_dw0(FM_MWR32_MIN) → type=MemWrite32, length=1");
}

#[test]
#[ignore = "pending: FlitDW0 struct not yet implemented (Tier 1)"]
fn flit_t1_uiomrd64_dw0_fields() {
    todo!("FlitDW0::from_dw0(FM_UIOMRD64_MIN) → type=UioMemRead, length=2");
}

#[test]
#[ignore = "pending: FlitDW0 struct not yet implemented (Tier 1)"]
fn flit_t1_cas32_dw0_length_is_2() {
    todo!("FlitDW0::from_dw0(FM_CAS32) → length=2 (2 DW payload: compare + swap)");
}

// ============================================================================
// Tier 2 — Per-vector header + size validation
//
// #[ignore] — pending: FlitTlpType enum and type-to-header-size table
//
// Unlock: add `pub enum FlitTlpType` and a function to compute:
//   header_bytes = (base_header_dw(type) + ohc_count) * 4
//   total_bytes  = header_bytes + length_dw * 4
// ============================================================================

#[test]
#[ignore = "pending: FlitTlpType enum not yet implemented (Tier 2)"]
fn flit_t2_nop_sizes() {
    todo!(
        "FM_NOP: FlitTlpType::Nop, base_header=1DW, ohc=0, payload=0DW, total=4B"
    );
}

#[test]
#[ignore = "pending: FlitTlpType enum not yet implemented (Tier 2)"]
fn flit_t2_mrd32_min_sizes() {
    todo!(
        "FM_MRD32_MIN: FlitTlpType::MemRead32, base=3DW, ohc=0, payload=0DW (read!), total=12B"
    );
}

#[test]
#[ignore = "pending: FlitTlpType enum not yet implemented (Tier 2)"]
fn flit_t2_mrd32_a1_sizes() {
    todo!(
        "FM_MRD32_A1_PASID: base=3DW, ohc=1DW, payload=0DW, total=16B"
    );
}

#[test]
#[ignore = "pending: FlitTlpType enum not yet implemented (Tier 2)"]
fn flit_t2_mwr32_min_sizes() {
    todo!(
        "FM_MWR32_MIN: base=3DW, ohc=0, payload=1DW, total=16B"
    );
}

#[test]
#[ignore = "pending: FlitTlpType enum not yet implemented (Tier 2)"]
fn flit_t2_mwr32_partial_a1_sizes() {
    todo!(
        "FM_MWR32_PARTIAL_A1: base=3DW, ohc=1DW, payload=1DW, total=20B"
    );
}

#[test]
#[ignore = "pending: FlitTlpType enum not yet implemented (Tier 2)"]
fn flit_t2_iowr_a2_sizes() {
    todo!(
        "FM_IOWR_A2: FlitTlpType::IoWrite, base=3DW, ohc=1DW, payload=1DW, total=20B"
    );
}

#[test]
#[ignore = "pending: FlitTlpType enum not yet implemented (Tier 2)"]
fn flit_t2_cfgwr0_a3_sizes() {
    todo!(
        "FM_CFGWR0_A3: FlitTlpType::CfgWrite0, base=3DW, ohc=1DW, payload=1DW, total=20B"
    );
}

#[test]
#[ignore = "pending: FlitTlpType enum not yet implemented (Tier 2)"]
fn flit_t2_uiomrd64_sizes() {
    todo!(
        "FM_UIOMRD64_MIN: FlitTlpType::UioMemRead, base=4DW, ohc=0, payload=0DW, total=16B"
    );
}

#[test]
#[ignore = "pending: FlitTlpType enum not yet implemented (Tier 2)"]
fn flit_t2_uiomwr64_sizes() {
    todo!(
        "FM_UIOMWR64_MIN: FlitTlpType::UioMemWrite, base=4DW, ohc=0, payload=2DW, total=24B"
    );
}

#[test]
#[ignore = "pending: FlitTlpType enum not yet implemented (Tier 2)"]
fn flit_t2_cas32_sizes() {
    todo!(
        "FM_CAS32: FlitTlpType::CompareSwap32, base=3DW, ohc=0, payload=2DW, total=20B"
    );
}

#[test]
#[ignore = "pending: FlitTlpType enum not yet implemented (Tier 2)"]
fn flit_t2_dmwr32_type_and_sizes() {
    todo!(
        "FM_DMWR32: FlitTlpType::DeferrableMemWrite32, base=3DW, ohc=0, payload=1DW, total=16B"
    );
}

// ============================================================================
// Tier 3 — OHC field parsing and mandatory OHC validation
//
// #[ignore] — pending: OHC parser + TlpError::MissingMandatoryOhc variant
//
// Unlock:
//   - `pub struct FlitOhc { a1: Option<OhcA1>, ... }`
//   - `TlpError::MissingMandatoryOhc`
//   - Parser enforces: IO requires OHC-A2, Config requires OHC-A3
// ============================================================================

#[test]
#[ignore = "pending: OHC parser not yet implemented (Tier 3)"]
fn flit_t3_mrd32_a1_pasid_extraction() {
    todo!(
        "FM_MRD32_A1_PASID: OHC-A1 word = [0x01,0x23,0x45,0x0F]
         → PASID = 0x12345, fdwbe = 0xF, ldwbe = 0x0"
    );
}

#[test]
#[ignore = "pending: OHC parser not yet implemented (Tier 3)"]
fn flit_t3_mwr32_partial_a1_be_extraction() {
    todo!(
        "FM_MWR32_PARTIAL_A1: OHC-A1 word = [0x00,0x00,0x00,0x03]
         → fdwbe = 0x3 (partial-byte write), ldwbe = 0x0"
    );
}

#[test]
#[ignore = "pending: OHC parser not yet implemented (Tier 3)"]
fn flit_t3_iowr_a2_mandatory_ohc_present() {
    todo!(
        "FM_IOWR_A2: OHC-A2 present (byte1 bit0=1)
         → parser succeeds and extracts fdwbe=0xF"
    );
}

#[test]
#[ignore = "pending: OHC parser not yet implemented (Tier 3)"]
fn flit_t3_iowr_missing_mandatory_ohc_a2() {
    // Negative test: FM_IOWR_A2 with byte1 cleared (no OHC declared)
    // Expected: Err(TlpError::MissingMandatoryOhc)
    let mut bad = FM_IOWR_A2.to_vec();
    bad[1] = 0x00; // clear OHC flags — mandatory OHC-A2 missing
    todo!(
        "parse_flit_tlp(&bad) → Err(TlpError::MissingMandatoryOhc)"
    );
}

#[test]
#[ignore = "pending: OHC parser not yet implemented (Tier 3)"]
fn flit_t3_cfgwr0_a3_mandatory_ohc_present() {
    todo!(
        "FM_CFGWR0_A3: OHC-A3 present
         → parser succeeds and extracts fdwbe=0xF"
    );
}

#[test]
#[ignore = "pending: OHC parser not yet implemented (Tier 3)"]
fn flit_t3_cfgwr_missing_mandatory_ohc_a3() {
    // Negative test: FM_CFGWR0_A3 with byte1 cleared
    let mut bad = FM_CFGWR0_A3.to_vec();
    bad[1] = 0x00; // clear OHC flags — mandatory OHC-A3 missing
    todo!(
        "parse_flit_tlp(&bad) → Err(TlpError::MissingMandatoryOhc)"
    );
}

// ============================================================================
// Tier 4 — Packed stream walking
//
// #[ignore] — pending: FlitStreamWalker or equivalent iterator in src/lib.rs
//
// Unlock: `pub struct FlitStreamWalker<'a>` or `flit_stream_iter(bytes: &[u8])`
//   yields `(offset: usize, FlitTlpType, total_size: usize)` for each TLP
// ============================================================================

#[test]
#[ignore = "pending: FlitStreamWalker not yet implemented (Tier 4)"]
fn flit_t4_stream_fragment_0_offsets() {
    // FM_STREAM_FRAGMENT_0 contains 4 back-to-back TLPs:
    //   offset  0 → NOP,     size  4B
    //   offset  4 → MRd32,   size 12B
    //   offset 16 → MWr32,   size 16B
    //   offset 32 → UIOMRd,  size 16B
    //   offset 48 → end
    todo!(
        "let walker = FlitStreamWalker::new(&FM_STREAM_FRAGMENT_0);
         let entries: Vec<_> = walker.collect();
         assert_eq!(entries[0], (0,  FlitTlpType::Nop,       4));
         assert_eq!(entries[1], (4,  FlitTlpType::MemRead32, 12));
         assert_eq!(entries[2], (16, FlitTlpType::MemWrite32,16));
         assert_eq!(entries[3], (32, FlitTlpType::UioMemRead,16));
         assert_eq!(entries.len(), 4);"
    );
}

#[test]
#[ignore = "pending: FlitStreamWalker not yet implemented (Tier 4)"]
fn flit_t4_stream_truncated_payload_error() {
    // FM_UIOMWR64_MIN with last byte removed → total-size check must fail
    let mut truncated = FM_UIOMWR64_MIN.to_vec();
    truncated.pop();
    todo!(
        "FlitStreamWalker::new(&truncated).next() → Err(TlpError::InvalidLength)"
    );
}

// ============================================================================
// Tier 5 — End-to-end TlpMode::Flit pipeline
//
// #[ignore] — pending: TlpPacket::new_flit() fully wired in src/lib.rs
//
// Unlock: `TlpMode::Flit` no longer returns `NotImplemented`; instead calls
//   `TlpPacket::new_flit(bytes)` which uses FlitDW0 + OHC parser.
// ============================================================================

#[test]
#[ignore = "pending: TlpMode::Flit not yet implemented (Tier 5)"]
fn flit_t5_end_to_end_mrd32_min() {
    todo!(
        "TlpPacket::new(FM_MRD32_MIN.to_vec(), TlpMode::Flit).unwrap()
         → get_flit_type() == FlitTlpType::MemRead32
         → get_data() is empty (read request, no payload)"
    );
}

#[test]
#[ignore = "pending: TlpMode::Flit not yet implemented (Tier 5)"]
fn flit_t5_end_to_end_mwr32_min() {
    todo!(
        "TlpPacket::new(FM_MWR32_MIN.to_vec(), TlpMode::Flit).unwrap()
         → get_flit_type() == FlitTlpType::MemWrite32
         → get_data() == [0xDE, 0xAD, 0xBE, 0xEF]"
    );
}

#[test]
#[ignore = "pending: TlpMode::Flit not yet implemented (Tier 5)"]
fn flit_t5_end_to_end_cas32() {
    todo!(
        "TlpPacket::new(FM_CAS32.to_vec(), TlpMode::Flit).unwrap()
         → flit type == FlitTlpType::CompareSwap32
         → payload == [0x11,0x11,0x11,0x11, 0x22,0x22,0x22,0x22]"
    );
}

#[test]
#[ignore = "pending: TlpMode::Flit not yet implemented (Tier 5)"]
fn flit_t5_end_to_end_dmwr32() {
    todo!(
        "TlpPacket::new(FM_DMWR32.to_vec(), TlpMode::Flit).unwrap()
         → flit type == FlitTlpType::DeferrableMemWrite32
         → payload == [0xC0, 0xFF, 0xEE, 0x00]"
    );
}

#[test]
#[ignore = "pending: TlpMode::Flit not yet implemented (Tier 5)"]
fn flit_t5_end_to_end_uiomwr64() {
    todo!(
        "TlpPacket::new(FM_UIOMWR64_MIN.to_vec(), TlpMode::Flit).unwrap()
         → flit type == FlitTlpType::UioMemWrite
         → payload == [0x11,0x22,0x33,0x44, 0x55,0x66,0x77,0x88]"
    );
}

#[test]
#[ignore = "pending: TlpMode::Flit not yet implemented (Tier 5)"]
fn flit_t5_nop_has_no_data() {
    todo!(
        "TlpPacket::new(FM_NOP.to_vec(), TlpMode::Flit).unwrap()
         → flit type == FlitTlpType::Nop
         → get_data().is_empty()"
    );
}
