# Changelog

All notable changes to `rtlp_lib` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.1] - 2026-04-24

### Added

- **`Display` implementation for `TlpPacket` and `TlpPacketHeader`** —
  one-line, Wireshark-style packet summaries suitable for logs and trace output.
  Both non-flit and flit-mode packets are supported. Examples:
  ```text
  MRd32 len=1 req=0400 tag=20 addr=F620000C
  MWr64 len=4 req=BEEF tag=A5 addr=100000000
  CplD len=1 cpl=2001 req=0400 tag=AB stat=0 bc=252
  CfgRd0 len=1 req=0100 tag=01 bus=02 dev=03 fn=0 reg=10
  Msg len=0 req=ABCD tag=01 code=7F
  FAdd len=1 req=DEAD tag=42 addr=C0010004
  Flit:MWr32 len=4 tc=0 ohc=1
  Flit:NOP
  ```
  Display impls are total (never panic) and degrade gracefully on malformed input
  to `??? data=NB` or `<Mnemonic> len=N` fallback lines.

- **`serde` feature** (opt-in) — `Serialize`/`Deserialize` for all public value
  types: `TlpMode`, `TlpError`, `TlpFmt`, `TlpType`, `AtomicOp`, `AtomicWidth`,
  `FlitTlpType`, `FlitDW0`, `FlitOhcA`. Enable with:
  ```toml
  rtlp-lib = { version = "0.5.1", features = ["serde"] }
  ```
  `TlpPacket` and `TlpPacketHeader` are intentionally excluded — the underlying
  `bitfield!` macro does not support serde derives.

### Fixed

- Documentation accuracy: flit-mode framing description corrected — flit framing
  is a structural change (PCIe 6.0 Base Spec), not a speed-tier feature.

## [0.5.0] - 2026-03-16

### Added

- **Flit-mode (PCIe 6.0 Base Spec) support** via `TlpMode::Flit` in `TlpPacket::new`.
  - `FlitTlpType` enum — 13 flit-mode TLP type codes decoded from DW0 byte 0.
  - `FlitDW0` struct — parsed flit-mode DW0 with `from_dw0()`, `ohc_count()`, `total_bytes()`.
  - `FlitOhcA` struct — parsed OHC-A extension word with `from_bytes()`.
  - `FlitStreamWalker` iterator — walks a packed stream of back-to-back flit TLPs.
  - `TlpError::MissingMandatoryOhc` variant for I/O Write and Config Write missing required OHC.
  - `FlitDW0::validate_mandatory_ohc()` — enforces mandatory OHC rules for IoWrite and CfgWrite0.
  - `TlpMode::Flit` variant (PCIe 6.0+).

- **Preferred (non-`get_*`) method names** on public structs (Issue #1):
  - `TlpPacket::tlp_type()` — replaces `get_tlp_type()`.
  - `TlpPacket::tlp_format()` — replaces `get_tlp_format()`.
  - `TlpPacket::flit_type()` — replaces `get_flit_type()`.
  - `TlpPacket::header()` — replaces `get_header()`.
  - `TlpPacket::data()` — replaces `get_data()` (returns `&[u8]`, no allocation).
  - `TlpPacketHeader::tlp_type()` — replaces `get_tlp_type()`.

- **`TlpPacket::mode() -> TlpMode`** — returns the framing mode the packet was created
  with (`NonFlit` or `Flit`).  The idiomatic way to dispatch between the two API surfaces;
  more readable than `flit_type().is_some()` as a mode proxy.

- **Factory functions now accept `impl Into<Vec<u8>>`** for `new_conf_req`, `new_cmpl_req`,
  and `new_msg_req` (previously `Vec<u8>`).  `pkt.data()` (a `&[u8]`) can now be passed
  directly without a `.to_vec()` allocation at the call site.  `new_mem_req` already
  accepted `impl Into<Vec<u8>>`; all four functions are now consistent.

- **`TlpType::is_non_posted()`** and **`TlpType::is_posted()`** — classify transactions.

- **Atomic operation support** via `new_atomic_req()`, `AtomicRequest` trait, `AtomicOp`, `AtomicWidth`.

- **Deferrable Memory Write** (`TlpType::DeferrableMemWriteReq`, Fmt=3DW/4DW with data, Type=0b11011).

- **Manual `Debug` implementations** for `TlpPacket` and `TlpPacketHeader` (Issue #3).
  Fields: `format`, `type`, `tc`, `t9`, `t8`, `attr_b2`, `ln`, `th`, `td`, `ep`, `attr`, `at`, `length`.

- **`#![warn(missing_docs)]`** and **`#![deny(unsafe_code)]`** crate-level attributes.

- **CI workflow** (`.github/workflows/rust.yml`) expanded to four focused jobs:
  `fmt` (cargo fmt --check), `clippy` (-D warnings), `test`, `msrv` (Rust 1.85).

### Changed

- Twelve internal bitfield accessor methods on `TlpPacketHeader` narrowed from `pub` to
  `pub(crate)`: `get_format`, `get_type`, `get_t9`, `get_t8`, `get_attr_b2`, `get_ln`,
  `get_th`, `get_td`, `get_ep`, `get_attr`, `get_at`, `get_length` (Issue #2).
  `get_tc` remains `pub`.

### Deprecated

- `TlpPacket::get_tlp_type()` — use `tlp_type()` instead.
- `TlpPacket::get_tlp_format()` — use `tlp_format()` instead.
- `TlpPacket::get_flit_type()` — use `flit_type()` instead.
- `TlpPacket::get_header()` — use `header()` instead.
- `TlpPacket::get_data()` — use `data()` instead (non-allocating `&[u8]`).
- `TlpPacketHeader::get_tlp_type()` — use `tlp_type()` instead.

### Fixed

- `CompletionReqDW23::laddr()` now correctly returns all 7 bits of the Lower Address field
  (bit 6 was previously masked out).
- `MessageReqDW24::dw3()` and `dw4()` now preserve all 32 bits (upper 16 bits were previously
  truncated due to a `u16` return type in the underlying bitfield).


