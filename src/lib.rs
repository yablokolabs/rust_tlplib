use std::convert::TryFrom;
use std::fmt::Display;

#[macro_use]
extern crate bitfield;

/// Errors that can occur when parsing TLP packets
#[derive(Debug, Clone, PartialEq)]
pub enum TlpError {
    /// Invalid format field value (bits don't match any known format)
    InvalidFormat,
    /// Invalid type field value (bits don't match any known type encoding)
    InvalidType,
    /// Unsupported combination of format and type
    UnsupportedCombination,
    /// Payload/header byte slice is too short to contain the expected fields
    InvalidLength,
}

#[repr(u8)]
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum TlpFmt {
    NoDataHeader3DW = 0b000,
    NoDataHeader4DW = 0b001,
    WithDataHeader3DW = 0b010,
    WithDataHeader4DW = 0b011,
    TlpPrefix = 0b100,
}

impl Display for TlpFmt {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::result::Result<(), std::fmt::Error> {
        let name = match &self {
            TlpFmt::NoDataHeader3DW => "3DW no Data Header",
            TlpFmt::NoDataHeader4DW => "4DW no Data Header",
            TlpFmt::WithDataHeader3DW => "3DW with Data Header",
            TlpFmt::WithDataHeader4DW => "4DW with Data Header",
            TlpFmt::TlpPrefix => "Tlp Prefix",
        };
        write!(fmt, "{}", name)
    }
}

impl TryFrom<u32> for TlpFmt {
    type Error = TlpError;

    fn try_from(v: u32) -> Result<Self, Self::Error> {
        match v {
            x if x == TlpFmt::NoDataHeader3DW as u32 => Ok(TlpFmt::NoDataHeader3DW),
            x if x == TlpFmt::NoDataHeader4DW as u32 => Ok(TlpFmt::NoDataHeader4DW),
            x if x == TlpFmt::WithDataHeader3DW as u32 => Ok(TlpFmt::WithDataHeader3DW),
            x if x == TlpFmt::WithDataHeader4DW as u32 => Ok(TlpFmt::WithDataHeader4DW),
            x if x == TlpFmt::TlpPrefix as u32 => Ok(TlpFmt::TlpPrefix),
            _ => Err(TlpError::InvalidFormat),
        }
    }
}

/// Atomic operation discriminant
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum AtomicOp {
    FetchAdd,
    Swap,
    CompareSwap,
}

/// Operand width — derived from TLP format: 3DW → 32-bit, 4DW → 64-bit
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum AtomicWidth {
    W32,
    W64,
}

#[derive(PartialEq)]
pub enum TlpFormatEncodingType {
    MemoryRequest = 0b00000,
    MemoryLockRequest = 0b00001,
    IORequest = 0b00010,
    ConfigType0Request = 0b00100,
    ConfigType1Request = 0b00101,
    Completion = 0b01010,
    CompletionLocked = 0b01011,
    FetchAtomicOpRequest = 0b01100,
    UnconSwapAtomicOpRequest = 0b01101,
    CompSwapAtomicOpRequest = 0b01110,
    DeferrableMemoryWriteRequest = 0b11011,
}

impl TryFrom<u32> for TlpFormatEncodingType {
    type Error = TlpError;

    fn try_from(v: u32) -> Result<Self, Self::Error> {
        match v {
            x if x == TlpFormatEncodingType::MemoryRequest as u32 => {
                Ok(TlpFormatEncodingType::MemoryRequest)
            }
            x if x == TlpFormatEncodingType::MemoryLockRequest as u32 => {
                Ok(TlpFormatEncodingType::MemoryLockRequest)
            }
            x if x == TlpFormatEncodingType::IORequest as u32 => {
                Ok(TlpFormatEncodingType::IORequest)
            }
            x if x == TlpFormatEncodingType::ConfigType0Request as u32 => {
                Ok(TlpFormatEncodingType::ConfigType0Request)
            }
            x if x == TlpFormatEncodingType::ConfigType1Request as u32 => {
                Ok(TlpFormatEncodingType::ConfigType1Request)
            }
            x if x == TlpFormatEncodingType::Completion as u32 => {
                Ok(TlpFormatEncodingType::Completion)
            }
            x if x == TlpFormatEncodingType::CompletionLocked as u32 => {
                Ok(TlpFormatEncodingType::CompletionLocked)
            }
            x if x == TlpFormatEncodingType::FetchAtomicOpRequest as u32 => {
                Ok(TlpFormatEncodingType::FetchAtomicOpRequest)
            }
            x if x == TlpFormatEncodingType::UnconSwapAtomicOpRequest as u32 => {
                Ok(TlpFormatEncodingType::UnconSwapAtomicOpRequest)
            }
            x if x == TlpFormatEncodingType::CompSwapAtomicOpRequest as u32 => {
                Ok(TlpFormatEncodingType::CompSwapAtomicOpRequest)
            }
            x if x == TlpFormatEncodingType::DeferrableMemoryWriteRequest as u32 => {
                Ok(TlpFormatEncodingType::DeferrableMemoryWriteRequest)
            }
            _ => Err(TlpError::InvalidType),
        }
    }
}

#[derive(PartialEq, Debug)]
pub enum TlpType {
    MemReadReq,
    MemReadLockReq,
    MemWriteReq,
    IOReadReq,
    IOWriteReq,
    ConfType0ReadReq,
    ConfType0WriteReq,
    ConfType1ReadReq,
    ConfType1WriteReq,
    MsgReq,
    MsgReqData,
    Cpl,
    CplData,
    CplLocked,
    CplDataLocked,
    FetchAddAtomicOpReq,
    SwapAtomicOpReq,
    CompareSwapAtomicOpReq,
    DeferrableMemWriteReq,
    LocalTlpPrefix,
    EndToEndTlpPrefix,
}

impl Display for TlpType {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::result::Result<(), std::fmt::Error> {
        let name = match &self {
            TlpType::MemReadReq => "Memory Read Request",
            TlpType::MemReadLockReq => "Locked Memory Read Request",
            TlpType::MemWriteReq => "Memory Write Request",
            TlpType::IOReadReq => "IO Read Request",
            TlpType::IOWriteReq => "IO Write Request",
            TlpType::ConfType0ReadReq => "Type 0 Config Read Request",
            TlpType::ConfType0WriteReq => "Type 0 Config Write Request",
            TlpType::ConfType1ReadReq => "Type 1 Config Read Request",
            TlpType::ConfType1WriteReq => "Type 1 Config Write Request",
            TlpType::MsgReq => "Message Request",
            TlpType::MsgReqData => "Message with Data Request",
            TlpType::Cpl => "Completion",
            TlpType::CplData => "Completion with Data",
            TlpType::CplLocked => "Locked Completion",
            TlpType::CplDataLocked => "Locked Completion with Data",
            TlpType::FetchAddAtomicOpReq => "Fetch Add Atomic Op Request",
            TlpType::SwapAtomicOpReq => "Swap Atomic Op Request",
            TlpType::CompareSwapAtomicOpReq => "Compare Swap Atomic Op Request",
            TlpType::DeferrableMemWriteReq => "Deferrable Memory Write Request",
            TlpType::LocalTlpPrefix => "Local Tlp Prefix",
            TlpType::EndToEndTlpPrefix => "End To End Tlp Prefix",
        };
        write!(fmt, "{}", name)
    }
}

impl TlpType {
    /// Returns `true` for non-posted TLP types (requests that expect a Completion).
    pub fn is_non_posted(&self) -> bool {
        matches!(
            self,
            TlpType::MemReadReq
                | TlpType::MemReadLockReq
                | TlpType::IOReadReq
                | TlpType::IOWriteReq
                | TlpType::ConfType0ReadReq
                | TlpType::ConfType0WriteReq
                | TlpType::ConfType1ReadReq
                | TlpType::ConfType1WriteReq
                | TlpType::FetchAddAtomicOpReq
                | TlpType::SwapAtomicOpReq
                | TlpType::CompareSwapAtomicOpReq
                | TlpType::DeferrableMemWriteReq
        )
    }
}

bitfield! {
        struct TlpHeader(MSB0 [u8]);
        u32;
        get_format, _: 2, 0;
        get_type,   _: 7, 3;
        get_t9,     _: 8, 8;
        get_tc,     _: 11, 9;
        get_t8,     _: 12, 12;
        get_attr_b2, _: 13, 13;
        get_ln,     _: 14, 14;
        get_th,     _: 15, 15;
        get_td,     _: 16, 16;
        get_ep,     _: 17, 17;
        get_attr,   _: 19, 18;
        get_at,     _: 21, 20;
        get_length, _: 31, 22;
}

impl<T: AsRef<[u8]>> TlpHeader<T> {
    fn get_tlp_type(&self) -> Result<TlpType, TlpError> {
        let tlp_type = self.get_type();
        let tlp_fmt = self.get_format();

        match TlpFormatEncodingType::try_from(tlp_type) {
            Ok(TlpFormatEncodingType::MemoryRequest) => match TlpFmt::try_from(tlp_fmt) {
                Ok(TlpFmt::NoDataHeader3DW) => Ok(TlpType::MemReadReq),
                Ok(TlpFmt::NoDataHeader4DW) => Ok(TlpType::MemReadReq),
                Ok(TlpFmt::WithDataHeader3DW) => Ok(TlpType::MemWriteReq),
                Ok(TlpFmt::WithDataHeader4DW) => Ok(TlpType::MemWriteReq),
                Ok(_) => Err(TlpError::UnsupportedCombination),
                Err(e) => Err(e),
            },
            Ok(TlpFormatEncodingType::MemoryLockRequest) => match TlpFmt::try_from(tlp_fmt) {
                Ok(TlpFmt::NoDataHeader3DW) => Ok(TlpType::MemReadLockReq),
                Ok(TlpFmt::NoDataHeader4DW) => Ok(TlpType::MemReadLockReq),
                Ok(_) => Err(TlpError::UnsupportedCombination),
                Err(e) => Err(e),
            },
            Ok(TlpFormatEncodingType::IORequest) => match TlpFmt::try_from(tlp_fmt) {
                Ok(TlpFmt::NoDataHeader3DW) => Ok(TlpType::IOReadReq),
                Ok(TlpFmt::WithDataHeader3DW) => Ok(TlpType::IOWriteReq),
                Ok(_) => Err(TlpError::UnsupportedCombination),
                Err(e) => Err(e),
            },
            Ok(TlpFormatEncodingType::ConfigType0Request) => match TlpFmt::try_from(tlp_fmt) {
                Ok(TlpFmt::NoDataHeader3DW) => Ok(TlpType::ConfType0ReadReq),
                Ok(TlpFmt::WithDataHeader3DW) => Ok(TlpType::ConfType0WriteReq),
                Ok(_) => Err(TlpError::UnsupportedCombination),
                Err(e) => Err(e),
            },
            Ok(TlpFormatEncodingType::ConfigType1Request) => match TlpFmt::try_from(tlp_fmt) {
                Ok(TlpFmt::NoDataHeader3DW) => Ok(TlpType::ConfType1ReadReq),
                Ok(TlpFmt::WithDataHeader3DW) => Ok(TlpType::ConfType1WriteReq),
                Ok(_) => Err(TlpError::UnsupportedCombination),
                Err(e) => Err(e),
            },
            Ok(TlpFormatEncodingType::Completion) => match TlpFmt::try_from(tlp_fmt) {
                Ok(TlpFmt::NoDataHeader3DW) => Ok(TlpType::Cpl),
                Ok(TlpFmt::WithDataHeader3DW) => Ok(TlpType::CplData),
                Ok(_) => Err(TlpError::UnsupportedCombination),
                Err(e) => Err(e),
            },
            Ok(TlpFormatEncodingType::CompletionLocked) => match TlpFmt::try_from(tlp_fmt) {
                Ok(TlpFmt::NoDataHeader3DW) => Ok(TlpType::CplLocked),
                Ok(TlpFmt::WithDataHeader3DW) => Ok(TlpType::CplDataLocked),
                Ok(_) => Err(TlpError::UnsupportedCombination),
                Err(e) => Err(e),
            },
            Ok(TlpFormatEncodingType::FetchAtomicOpRequest) => match TlpFmt::try_from(tlp_fmt) {
                Ok(TlpFmt::WithDataHeader3DW) => Ok(TlpType::FetchAddAtomicOpReq),
                Ok(TlpFmt::WithDataHeader4DW) => Ok(TlpType::FetchAddAtomicOpReq),
                Ok(_) => Err(TlpError::UnsupportedCombination),
                Err(e) => Err(e),
            },
            Ok(TlpFormatEncodingType::UnconSwapAtomicOpRequest) => {
                match TlpFmt::try_from(tlp_fmt) {
                    Ok(TlpFmt::WithDataHeader3DW) => Ok(TlpType::SwapAtomicOpReq),
                    Ok(TlpFmt::WithDataHeader4DW) => Ok(TlpType::SwapAtomicOpReq),
                    Ok(_) => Err(TlpError::UnsupportedCombination),
                    Err(e) => Err(e),
                }
            }
            Ok(TlpFormatEncodingType::CompSwapAtomicOpRequest) => match TlpFmt::try_from(tlp_fmt) {
                Ok(TlpFmt::WithDataHeader3DW) => Ok(TlpType::CompareSwapAtomicOpReq),
                Ok(TlpFmt::WithDataHeader4DW) => Ok(TlpType::CompareSwapAtomicOpReq),
                Ok(_) => Err(TlpError::UnsupportedCombination),
                Err(e) => Err(e),
            },
            Ok(TlpFormatEncodingType::DeferrableMemoryWriteRequest) => {
                match TlpFmt::try_from(tlp_fmt) {
                    Ok(TlpFmt::WithDataHeader3DW) => Ok(TlpType::DeferrableMemWriteReq),
                    Ok(TlpFmt::WithDataHeader4DW) => Ok(TlpType::DeferrableMemWriteReq),
                    Ok(_) => Err(TlpError::UnsupportedCombination),
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(e),
        }
    }
}

/// Memory Request Trait:
/// Applies to 32 and 64 bits requests as well as legacy IO-Request
/// (Legacy IO Request has the same structure as MemRead3DW)
/// Software using the library may want to use trait instead of bitfield structures
/// Both 3DW (32-bit) and 4DW (64-bit) headers implement this trait
/// 3DW header is also used for all Legacy IO Requests.
pub trait MemRequest {
    fn address(&self) -> u64;
    fn req_id(&self) -> u16;
    fn tag(&self) -> u8;
    fn ldwbe(&self) -> u8;
    fn fdwbe(&self) -> u8;
}

// Structure for both 3DW Memory Request as well as Legacy IO Request
bitfield! {
    pub struct MemRequest3DW(MSB0 [u8]);
    u32;
    pub get_requester_id,   _: 15, 0;
    pub get_tag,            _: 23, 16;
    pub get_last_dw_be,     _: 27, 24;
    pub get_first_dw_be,    _: 31, 28;
    pub get_address32,      _: 63, 32;
}

bitfield! {
    pub struct MemRequest4DW(MSB0 [u8]);
    u64;
    pub get_requester_id,   _: 15, 0;
    pub get_tag,            _: 23, 16;
    pub get_last_dw_be,     _: 27, 24;
    pub get_first_dw_be,    _: 31, 28;
    pub get_address64,      _: 95, 32;
}

impl<T: AsRef<[u8]>> MemRequest for MemRequest3DW<T> {
    fn address(&self) -> u64 {
        self.get_address32().into()
    }
    fn req_id(&self) -> u16 {
        self.get_requester_id() as u16
    }
    fn tag(&self) -> u8 {
        self.get_tag() as u8
    }
    fn ldwbe(&self) -> u8 {
        self.get_last_dw_be() as u8
    }
    fn fdwbe(&self) -> u8 {
        self.get_first_dw_be() as u8
    }
}

impl<T: AsRef<[u8]>> MemRequest for MemRequest4DW<T> {
    fn address(&self) -> u64 {
        self.get_address64()
    }
    fn req_id(&self) -> u16 {
        self.get_requester_id() as u16
    }
    fn tag(&self) -> u8 {
        self.get_tag() as u8
    }
    fn ldwbe(&self) -> u8 {
        self.get_last_dw_be() as u8
    }
    fn fdwbe(&self) -> u8 {
        self.get_first_dw_be() as u8
    }
}

/// Obtain Memory Request trait from bytes in vector as dyn
/// This is preffered way of dealing with TLP headers as exact format (32/64 bits) is not required
///
/// # Examples
///
/// ```
/// use rtlp_lib::TlpPacket;
/// use rtlp_lib::TlpFmt;
/// use rtlp_lib::TlpError;
/// use rtlp_lib::MemRequest;
/// use rtlp_lib::new_mem_req;
///
/// fn decode(bytes: Vec<u8>) -> Result<(), TlpError> {
///     let tlp = TlpPacket::new(bytes)?;
///
///     let tlpfmt = tlp.get_tlp_format()?;
///     // MemRequest contains only fields specific to PCI Memory Requests
///     let mem_req: Box<dyn MemRequest> = new_mem_req(tlp.get_data(), &tlpfmt)?;
///
///     // Address is 64 bits regardless of TLP format
///     // println!("Memory Request Address: {:x}", mem_req.address());
///
///     // Format of TLP (3DW vs 4DW) is stored in the TLP header
///     println!("This TLP size is: {}", tlpfmt);
///     // Type LegacyIO vs MemRead vs MemWrite is stored in first DW of TLP
///     println!("This TLP type is: {:?}", tlp.get_tlp_type());
///     Ok(())
/// }
///
///
/// # let bytes = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
/// # decode(bytes).unwrap();
/// ```
pub fn new_mem_req(bytes: Vec<u8>, format: &TlpFmt) -> Result<Box<dyn MemRequest>, TlpError> {
    match format {
        TlpFmt::NoDataHeader3DW => Ok(Box::new(MemRequest3DW(bytes))),
        TlpFmt::NoDataHeader4DW => Ok(Box::new(MemRequest4DW(bytes))),
        TlpFmt::WithDataHeader3DW => Ok(Box::new(MemRequest3DW(bytes))),
        TlpFmt::WithDataHeader4DW => Ok(Box::new(MemRequest4DW(bytes))),
        TlpFmt::TlpPrefix => Err(TlpError::UnsupportedCombination),
    }
}

/// Configuration Request Trait:
/// Configuration Requests Headers are always same size (3DW),
/// this trait is provided to have same API as other headers with variable size
pub trait ConfigurationRequest {
    fn req_id(&self) -> u16;
    fn tag(&self) -> u8;
    fn bus_nr(&self) -> u8;
    fn dev_nr(&self) -> u8;
    fn func_nr(&self) -> u8;
    fn ext_reg_nr(&self) -> u8;
    fn reg_nr(&self) -> u8;
}

/// Obtain Configuration Request trait from bytes in vector as dyn
///
/// # Examples
///
/// ```
/// use std::convert::TryFrom;
///
/// use rtlp_lib::TlpPacket;
/// use rtlp_lib::TlpFmt;
/// use rtlp_lib::ConfigurationRequest;
/// use rtlp_lib::new_conf_req;
///
/// let bytes = vec![0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
/// let tlp = TlpPacket::new(bytes).unwrap();
///
/// if let Ok(tlpfmt) = tlp.get_tlp_format() {
///     let config_req: Box<dyn ConfigurationRequest> = new_conf_req(tlp.get_data(), &tlpfmt).unwrap();
///
///     //println!("Configuration Request Bus: {:x}", config_req.bus_nr());
/// }
/// ```
///
/// # Errors
///
/// This function only supports configuration requests with 3DW headers.
/// It returns an [`Err(TlpError::UnsupportedCombination)`](TlpError::UnsupportedCombination)
/// if `format` is not [`TlpFmt::NoDataHeader3DW`] or [`TlpFmt::WithDataHeader3DW`]
/// (for example, when using a 4DW header format or a TLP prefix).
pub fn new_conf_req(
    bytes: Vec<u8>,
    format: &TlpFmt,
) -> Result<Box<dyn ConfigurationRequest>, TlpError> {
    match format {
        TlpFmt::NoDataHeader3DW | TlpFmt::WithDataHeader3DW => Ok(Box::new(ConfigRequest(bytes))),
        _ => Err(TlpError::UnsupportedCombination),
    }
}

bitfield! {
    pub struct ConfigRequest(MSB0 [u8]);
    u32;
    pub get_requester_id,   _: 15, 0;
    pub get_tag,            _: 23, 16;
    pub get_last_dw_be,     _: 27, 24;
    pub get_first_dw_be,    _: 31, 28;
    pub get_bus_nr,         _: 39, 32;
    pub get_dev_nr,         _: 44, 40;
    pub get_func_nr,        _: 47, 45;
    pub rsvd,               _: 51, 48;
    pub get_ext_reg_nr,     _: 55, 52;
    pub get_register_nr,    _: 61, 56;
    r,                      _: 63, 62;
}

impl<T: AsRef<[u8]>> ConfigurationRequest for ConfigRequest<T> {
    fn req_id(&self) -> u16 {
        self.get_requester_id() as u16
    }
    fn tag(&self) -> u8 {
        self.get_tag() as u8
    }
    fn bus_nr(&self) -> u8 {
        self.get_bus_nr() as u8
    }
    fn dev_nr(&self) -> u8 {
        self.get_dev_nr() as u8
    }
    fn func_nr(&self) -> u8 {
        self.get_func_nr() as u8
    }
    fn ext_reg_nr(&self) -> u8 {
        self.get_ext_reg_nr() as u8
    }
    fn reg_nr(&self) -> u8 {
        self.get_register_nr() as u8
    }
}

/// Completion Request Trait
/// Completions are always 3DW (for with data (fmt = b010) and without data (fmt = b000) )
/// This trait is provided to have same API as other headers with variable size
/// To obtain this trait `new_cmpl_req()` function has to be used
/// Trait release user from dealing with bitfield structures.
pub trait CompletionRequest {
    fn cmpl_id(&self) -> u16;
    fn cmpl_stat(&self) -> u8;
    fn bcm(&self) -> u8;
    fn byte_cnt(&self) -> u16;
    fn req_id(&self) -> u16;
    fn tag(&self) -> u8;
    fn laddr(&self) -> u8;
}

bitfield! {
    pub struct CompletionReqDW23(MSB0 [u8]);
    u16;
    pub get_completer_id,   _: 15, 0;
    pub get_cmpl_stat,      _: 18, 16;
    pub get_bcm,            _: 19, 19;
    pub get_byte_cnt,       _: 31, 20;
    pub get_req_id,         _: 47, 32;
    pub get_tag,            _: 55, 48;
    r,                      _: 56, 56;
    pub get_laddr,          _: 63, 57;
}

impl<T: AsRef<[u8]>> CompletionRequest for CompletionReqDW23<T> {
    fn cmpl_id(&self) -> u16 {
        self.get_completer_id()
    }
    fn cmpl_stat(&self) -> u8 {
        self.get_cmpl_stat() as u8
    }
    fn bcm(&self) -> u8 {
        self.get_bcm() as u8
    }
    fn byte_cnt(&self) -> u16 {
        self.get_byte_cnt()
    }
    fn req_id(&self) -> u16 {
        self.get_req_id()
    }
    fn tag(&self) -> u8 {
        self.get_tag() as u8
    }
    fn laddr(&self) -> u8 {
        self.get_laddr() as u8
    }
}

/// Obtain Completion Request dyn Trait:
///
/// # Examples
///
/// ```
/// use rtlp_lib::TlpFmt;
/// use rtlp_lib::CompletionRequest;
/// use rtlp_lib::new_cmpl_req;
///
/// let bytes = vec![0x20, 0x01, 0xFF, 0xC2, 0x00, 0x00, 0x00, 0x00];
/// // TLP Format usually comes from TlpPacket or Header here we made up one for example
/// let tlpfmt = TlpFmt::WithDataHeader3DW;
///
/// let cmpl_req: Box<dyn CompletionRequest> = new_cmpl_req(bytes, &tlpfmt).unwrap();
///
/// println!("Requester ID from Completion{}", cmpl_req.req_id());
/// ```
pub fn new_cmpl_req(
    bytes: Vec<u8>,
    format: &TlpFmt,
) -> Result<Box<dyn CompletionRequest>, TlpError> {
    match format {
        TlpFmt::NoDataHeader3DW | TlpFmt::WithDataHeader3DW => {
            Ok(Box::new(CompletionReqDW23(bytes)))
        }
        _ => Err(TlpError::UnsupportedCombination),
    }
}

/// Message Request trait
/// Provide method to access fields in DW2-4 header is handled by TlpHeader
pub trait MessageRequest {
    fn req_id(&self) -> u16;
    fn tag(&self) -> u8;
    fn msg_code(&self) -> u8;
    /// DW3-4 vary with Message Code Field
    fn dw3(&self) -> u32;
    fn dw4(&self) -> u32;
}

bitfield! {
    pub struct MessageReqDW24(MSB0 [u8]);
    u32;
    pub get_requester_id,   _: 15, 0;
    pub get_tag,            _: 23, 16;
    pub get_msg_code,       _: 31, 24;
    pub get_dw3,            _: 63, 32;
    pub get_dw4,            _: 95, 64;
}

impl<T: AsRef<[u8]>> MessageRequest for MessageReqDW24<T> {
    fn req_id(&self) -> u16 {
        self.get_requester_id() as u16
    }
    fn tag(&self) -> u8 {
        self.get_tag() as u8
    }
    fn msg_code(&self) -> u8 {
        self.get_msg_code() as u8
    }
    fn dw3(&self) -> u32 {
        self.get_dw3()
    }
    fn dw4(&self) -> u32 {
        self.get_dw4()
    }
    // TODO: implement routedby method based on type
}

/// Obtain Message Request dyn Trait:
///
/// # Examples
///
/// ```
/// use rtlp_lib::TlpFmt;
/// use rtlp_lib::MessageRequest;
/// use rtlp_lib::new_msg_req;
///
/// let bytes = vec![0x20, 0x01, 0xFF, 0xC2, 0x00, 0x00, 0x00, 0x00];
/// let tlpfmt = TlpFmt::NoDataHeader3DW;
///
/// let msg_req: Box<dyn MessageRequest> = new_msg_req(bytes, &tlpfmt).unwrap();
///
/// println!("Requester ID from Message{}", msg_req.req_id());
/// ```
pub fn new_msg_req(bytes: Vec<u8>, format: &TlpFmt) -> Result<Box<dyn MessageRequest>, TlpError> {
    match format {
        TlpFmt::NoDataHeader3DW
        | TlpFmt::NoDataHeader4DW
        | TlpFmt::WithDataHeader3DW
        | TlpFmt::WithDataHeader4DW => Ok(Box::new(MessageReqDW24(bytes))),
        TlpFmt::TlpPrefix => Err(TlpError::UnsupportedCombination),
    }
}

/// Atomic Request trait: header fields and operand(s) for atomic op TLPs.
/// Use `new_atomic_req()` to obtain a trait object from raw packet bytes.
pub trait AtomicRequest: std::fmt::Debug {
    fn op(&self) -> AtomicOp;
    fn width(&self) -> AtomicWidth;
    fn req_id(&self) -> u16;
    fn tag(&self) -> u8;
    fn address(&self) -> u64;
    /// Primary operand: addend (FetchAdd), new value (Swap), compare value (CAS)
    fn operand0(&self) -> u64;
    /// Second operand: swap value for CAS; `None` for FetchAdd and Swap
    fn operand1(&self) -> Option<u64>;
}

#[derive(Debug)]
struct AtomicReq {
    op: AtomicOp,
    width: AtomicWidth,
    req_id: u16,
    tag: u8,
    address: u64,
    operand0: u64,
    operand1: Option<u64>,
}

impl AtomicRequest for AtomicReq {
    fn op(&self) -> AtomicOp {
        self.op
    }
    fn width(&self) -> AtomicWidth {
        self.width
    }
    fn req_id(&self) -> u16 {
        self.req_id
    }
    fn tag(&self) -> u8 {
        self.tag
    }
    fn address(&self) -> u64 {
        self.address
    }
    fn operand0(&self) -> u64 {
        self.operand0
    }
    fn operand1(&self) -> Option<u64> {
        self.operand1
    }
}

fn read_operand_be(b: &[u8], off: usize, width: AtomicWidth) -> u64 {
    match width {
        AtomicWidth::W32 => u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]]) as u64,
        AtomicWidth::W64 => u64::from_be_bytes([
            b[off],
            b[off + 1],
            b[off + 2],
            b[off + 3],
            b[off + 4],
            b[off + 5],
            b[off + 6],
            b[off + 7],
        ]),
    }
}

/// Parse an atomic TLP request from a `TlpPacket`.
///
/// The TLP type and format are extracted from the packet header.
/// Returns `Err(TlpError::UnsupportedCombination)` if the packet does not
/// encode one of the three atomic op types, and `Err(TlpError::InvalidLength)`
/// if the data payload has the wrong size for the expected header and operands.
///
/// # Examples
///
/// ```
/// use rtlp_lib::{TlpPacket, AtomicRequest, new_atomic_req};
///
/// // FetchAdd 3DW: DW0 byte0 = (fmt=0b010 << 5) | typ=0b01100 = 0x4C
/// let bytes = vec![
///     0x4C, 0x00, 0x00, 0x00, // DW0: WithDataHeader3DW / FetchAdd
///     0xAB, 0xCD, 0x01, 0x00, // DW1: req_id=0xABCD tag=1 BE=0
///     0x00, 0x00, 0x10, 0x00, // DW2: address32=0x0000_1000
///     0x00, 0x00, 0x00, 0x04, // operand: addend=4
/// ];
/// let pkt = TlpPacket::new(bytes).unwrap();
/// let ar = new_atomic_req(&pkt).unwrap();
/// assert_eq!(ar.req_id(),   0xABCD);
/// assert_eq!(ar.operand0(), 4);
/// assert!(ar.operand1().is_none());
/// ```
pub fn new_atomic_req(pkt: &TlpPacket) -> Result<Box<dyn AtomicRequest>, TlpError> {
    let tlp_type = pkt.get_tlp_type()?;
    let format = pkt.get_tlp_format()?;
    let bytes = pkt.get_data();

    let op = match tlp_type {
        TlpType::FetchAddAtomicOpReq => AtomicOp::FetchAdd,
        TlpType::SwapAtomicOpReq => AtomicOp::Swap,
        TlpType::CompareSwapAtomicOpReq => AtomicOp::CompareSwap,
        _ => return Err(TlpError::UnsupportedCombination),
    };
    let (width, hdr_len) = match format {
        TlpFmt::WithDataHeader3DW => (AtomicWidth::W32, 8usize),
        TlpFmt::WithDataHeader4DW => (AtomicWidth::W64, 12usize),
        _ => return Err(TlpError::UnsupportedCombination),
    };

    let op_size = match width {
        AtomicWidth::W32 => 4usize,
        AtomicWidth::W64 => 8usize,
    };
    let num_ops = if matches!(op, AtomicOp::CompareSwap) {
        2
    } else {
        1
    };
    let needed = hdr_len + op_size * num_ops;
    if bytes.len() != needed {
        return Err(TlpError::InvalidLength);
    }

    let req_id = u16::from_be_bytes([bytes[0], bytes[1]]);
    let tag = bytes[2];
    let address = match width {
        AtomicWidth::W32 => u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as u64,
        AtomicWidth::W64 => u64::from_be_bytes([
            bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11],
        ]),
    };

    let operand0 = read_operand_be(&bytes, hdr_len, width);
    let operand1 = if matches!(op, AtomicOp::CompareSwap) {
        Some(read_operand_be(&bytes, hdr_len + op_size, width))
    } else {
        None
    };

    Ok(Box::new(AtomicReq {
        op,
        width,
        req_id,
        tag,
        address,
        operand0,
        operand1,
    }))
}

/// TLP Packet Header
/// Contains bytes for Packet header and informations about TLP type
pub struct TlpPacketHeader {
    header: TlpHeader<Vec<u8>>,
}

impl TlpPacketHeader {
    pub fn new(bytes: Vec<u8>) -> Result<TlpPacketHeader, TlpError> {
        if bytes.len() < 4 {
            return Err(TlpError::InvalidLength);
        }
        let mut dw0 = vec![0; 4];
        dw0[..4].clone_from_slice(&bytes[0..4]);

        Ok(TlpPacketHeader {
            header: TlpHeader(dw0),
        })
    }

    pub fn get_tlp_type(&self) -> Result<TlpType, TlpError> {
        self.header.get_tlp_type()
    }

    pub fn get_format(&self) -> u32 {
        self.header.get_format()
    }
    pub fn get_type(&self) -> u32 {
        self.header.get_type()
    }
    pub fn get_t9(&self) -> u32 {
        self.header.get_t9()
    }
    pub fn get_tc(&self) -> u32 {
        self.header.get_tc()
    }
    pub fn get_t8(&self) -> u32 {
        self.header.get_t8()
    }
    pub fn get_attr_b2(&self) -> u32 {
        self.header.get_attr_b2()
    }
    pub fn get_ln(&self) -> u32 {
        self.header.get_ln()
    }
    pub fn get_th(&self) -> u32 {
        self.header.get_th()
    }
    pub fn get_td(&self) -> u32 {
        self.header.get_td()
    }
    pub fn get_ep(&self) -> u32 {
        self.header.get_ep()
    }
    pub fn get_attr(&self) -> u32 {
        self.header.get_attr()
    }
    pub fn get_at(&self) -> u32 {
        self.header.get_at()
    }
    pub fn get_length(&self) -> u32 {
        self.header.get_length()
    }
}

/// TLP Packet structure is high level abstraction for entire TLP packet
/// Contains Header and Data
///
/// # Examples
///
/// ```
/// use rtlp_lib::TlpPacket;
/// use rtlp_lib::TlpFmt;
/// use rtlp_lib::TlpType;
/// use rtlp_lib::new_msg_req;
/// use rtlp_lib::new_conf_req;
/// use rtlp_lib::new_mem_req;
/// use rtlp_lib::new_cmpl_req;
///
/// // Bytes for full TLP Packet
/// //               <------- DW1 -------->  <------- DW2 -------->  <------- DW3 -------->  <------- DW4 -------->
/// let bytes = vec![0x00, 0x00, 0x20, 0x01, 0x04, 0x00, 0x00, 0x01, 0x20, 0x01, 0xFF, 0x00, 0xC2, 0x81, 0xFF, 0x10];
/// let packet = TlpPacket::new(bytes).unwrap();
///
/// let header = packet.get_header();
/// // TLP Type tells us what is this packet
/// let tlp_type = header.get_tlp_type().unwrap();
/// let tlp_format = packet.get_tlp_format().unwrap();
/// let requester_id;
/// match (tlp_type) {
///      TlpType::MemReadReq |
///      TlpType::MemReadLockReq |
///      TlpType::MemWriteReq |
///      TlpType::DeferrableMemWriteReq |
///      TlpType::IOReadReq |
///      TlpType::IOWriteReq |
///      TlpType::FetchAddAtomicOpReq |
///      TlpType::SwapAtomicOpReq |
///      TlpType::CompareSwapAtomicOpReq => requester_id = new_mem_req(packet.get_data(), &tlp_format).unwrap().req_id(),
///      TlpType::ConfType0ReadReq |
///      TlpType::ConfType0WriteReq |
///      TlpType::ConfType1ReadReq |
///      TlpType::ConfType1WriteReq => requester_id = new_conf_req(packet.get_data(), &tlp_format).unwrap().req_id(),
///      TlpType::MsgReq |
///      TlpType::MsgReqData => requester_id = new_msg_req(packet.get_data(), &tlp_format).unwrap().req_id(),
///      TlpType::Cpl |
///      TlpType::CplData |
///      TlpType::CplLocked |
///      TlpType::CplDataLocked => requester_id = new_cmpl_req(packet.get_data(), &tlp_format).unwrap().req_id(),
///      TlpType::LocalTlpPrefix |
///      TlpType::EndToEndTlpPrefix => println!("I need to implement TLP Type: {:?}", tlp_type),
/// }
/// ```
pub struct TlpPacket {
    header: TlpPacketHeader,
    data: Vec<u8>,
}

impl TlpPacket {
    pub fn new(bytes: Vec<u8>) -> Result<TlpPacket, TlpError> {
        if bytes.len() < 4 {
            return Err(TlpError::InvalidLength);
        }
        let mut ownbytes = bytes.to_vec();
        let mut header = vec![0; 4];
        header.clone_from_slice(&ownbytes[0..4]);
        let data = ownbytes.drain(4..).collect();
        Ok(TlpPacket {
            header: TlpPacketHeader::new(header)?,
            data,
        })
    }

    pub fn get_header(&self) -> &TlpPacketHeader {
        &self.header
    }

    pub fn get_data(&self) -> Vec<u8> {
        self.data.to_vec()
    }

    pub fn get_tlp_type(&self) -> Result<TlpType, TlpError> {
        self.header.get_tlp_type()
    }

    pub fn get_tlp_format(&self) -> Result<TlpFmt, TlpError> {
        TlpFmt::try_from(self.header.get_format())
    }
}

// ─── TLP Encoder / Builder API ──────────────────────────────────────────────

/// Helper: build DW0 from format, type-encoding, and payload length (in DWs).
///
/// Header fields TC, TD, EP, Attr, AT, etc. default to 0.
fn build_dw0(fmt: TlpFmt, type_enc: TlpFormatEncodingType, length: u16) -> [u8; 4] {
    let fmt_bits = fmt as u8 & 0x7;
    let type_bits = type_enc as u8 & 0x1f;
    let len = length & 0x3ff;
    [
        (fmt_bits << 5) | type_bits, // byte0: fmt(3) | type(5)
        0x00,                        // byte1: T9, TC, T8, Attr_b2, LN, TH — all 0
        ((len >> 8) & 0x3) as u8,    // byte2: TD, EP, Attr, AT, Length[9:8]
        (len & 0xff) as u8,          // byte3: Length[7:0]
    ]
}

/// Builder for Memory Read and Write TLP packets.
///
/// Supports both 32-bit (3DW) and 64-bit (4DW) addressing.
/// The format is auto-selected based on the address:
/// - address ≤ 0xFFFF_FFFF → 3DW header
/// - address > 0xFFFF_FFFF → 4DW header
///
/// For writes, call `.data()` to attach a payload.
///
/// # Examples
///
/// ```
/// use rtlp_lib::{MemRequestBuilder, TlpPacket, TlpType};
///
/// // 32-bit memory read, 1 DW
/// let bytes = MemRequestBuilder::new()
///     .requester_id(0x0100)
///     .tag(0x20)
///     .address(0xF620_000C)
///     .first_dw_be(0x0F)
///     .length(1)
///     .build();
///
/// let pkt = TlpPacket::new(bytes).unwrap();
/// assert_eq!(pkt.get_tlp_type().unwrap(), TlpType::MemReadReq);
/// ```
pub struct MemRequestBuilder {
    requester_id: u16,
    tag: u8,
    first_dw_be: u8,
    last_dw_be: u8,
    address: u64,
    length: u16,
    data: Option<Vec<u8>>,
}

impl MemRequestBuilder {
    pub fn new() -> Self {
        MemRequestBuilder {
            requester_id: 0,
            tag: 0,
            first_dw_be: 0x0F,
            last_dw_be: 0x00,
            address: 0,
            length: 0,
            data: None,
        }
    }

    pub fn requester_id(mut self, id: u16) -> Self {
        self.requester_id = id;
        self
    }
    pub fn tag(mut self, tag: u8) -> Self {
        self.tag = tag;
        self
    }
    pub fn first_dw_be(mut self, be: u8) -> Self {
        self.first_dw_be = be & 0x0F;
        self
    }
    pub fn last_dw_be(mut self, be: u8) -> Self {
        self.last_dw_be = be & 0x0F;
        self
    }
    pub fn address(mut self, addr: u64) -> Self {
        self.address = addr;
        self
    }
    pub fn length(mut self, len: u16) -> Self {
        self.length = len & 0x3ff;
        self
    }
    /// Attach write data payload. Setting data makes this a MemWrite.
    pub fn data(mut self, payload: Vec<u8>) -> Self {
        self.data = Some(payload);
        self
    }

    /// Build the TLP packet bytes.
    pub fn build(self) -> Vec<u8> {
        let is_write = self.data.is_some();
        let is_4dw = self.address > 0xFFFF_FFFF;

        let fmt = match (is_write, is_4dw) {
            (false, false) => TlpFmt::NoDataHeader3DW,
            (false, true) => TlpFmt::NoDataHeader4DW,
            (true, false) => TlpFmt::WithDataHeader3DW,
            (true, true) => TlpFmt::WithDataHeader4DW,
        };

        let dw0 = build_dw0(fmt, TlpFormatEncodingType::MemoryRequest, self.length);
        let mut pkt = Vec::from(dw0);

        // DW1: requester_id(16) | tag(8) | last_dw_be(4) | first_dw_be(4)
        pkt.push((self.requester_id >> 8) as u8);
        pkt.push(self.requester_id as u8);
        pkt.push(self.tag);
        pkt.push((self.last_dw_be << 4) | self.first_dw_be);

        if is_4dw {
            // DW2-DW3: address64
            pkt.extend_from_slice(&self.address.to_be_bytes());
        } else {
            // DW2: address32
            pkt.extend_from_slice(&(self.address as u32).to_be_bytes());
        }

        if let Some(payload) = self.data {
            pkt.extend_from_slice(&payload);
        }

        pkt
    }
}

impl Default for MemRequestBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for Configuration Read/Write TLP packets.
///
/// Config TLPs are always 3DW. Use `.data()` to make it a write.
///
/// # Examples
///
/// ```
/// use rtlp_lib::{ConfigRequestBuilder, TlpPacket, TlpType};
///
/// let bytes = ConfigRequestBuilder::new()
///     .requester_id(0x0100)
///     .tag(0x01)
///     .bus(0x02)
///     .device(0x03)
///     .function(0x00)
///     .register(0x10)
///     .length(1)
///     .build();
///
/// let pkt = TlpPacket::new(bytes).unwrap();
/// assert_eq!(pkt.get_tlp_type().unwrap(), TlpType::ConfType0ReadReq);
/// ```
pub struct ConfigRequestBuilder {
    requester_id: u16,
    tag: u8,
    first_dw_be: u8,
    last_dw_be: u8,
    bus: u8,
    device: u8,
    function: u8,
    ext_reg: u8,
    register: u8,
    length: u16,
    config_type: u8, // 0 or 1
    data: Option<Vec<u8>>,
}

impl ConfigRequestBuilder {
    pub fn new() -> Self {
        ConfigRequestBuilder {
            requester_id: 0,
            tag: 0,
            first_dw_be: 0x0F,
            last_dw_be: 0x00,
            bus: 0,
            device: 0,
            function: 0,
            ext_reg: 0,
            register: 0,
            length: 0,
            config_type: 0,
            data: None,
        }
    }

    pub fn requester_id(mut self, id: u16) -> Self {
        self.requester_id = id;
        self
    }
    pub fn tag(mut self, tag: u8) -> Self {
        self.tag = tag;
        self
    }
    pub fn first_dw_be(mut self, be: u8) -> Self {
        self.first_dw_be = be & 0x0F;
        self
    }
    pub fn last_dw_be(mut self, be: u8) -> Self {
        self.last_dw_be = be & 0x0F;
        self
    }
    pub fn bus(mut self, bus: u8) -> Self {
        self.bus = bus;
        self
    }
    pub fn device(mut self, dev: u8) -> Self {
        self.device = dev & 0x1F;
        self
    }
    pub fn function(mut self, func: u8) -> Self {
        self.function = func & 0x07;
        self
    }
    pub fn ext_register(mut self, ext: u8) -> Self {
        self.ext_reg = ext & 0x0F;
        self
    }
    pub fn register(mut self, reg: u8) -> Self {
        self.register = reg & 0x3F;
        self
    }
    pub fn length(mut self, len: u16) -> Self {
        self.length = len & 0x3ff;
        self
    }
    /// Set config type: 0 (default) or 1.
    pub fn config_type(mut self, ct: u8) -> Self {
        self.config_type = ct & 1;
        self
    }
    /// Attach write data payload. Setting data makes this a CfgWr.
    pub fn data(mut self, payload: Vec<u8>) -> Self {
        self.data = Some(payload);
        self
    }

    pub fn build(self) -> Vec<u8> {
        let is_write = self.data.is_some();
        let fmt = if is_write {
            TlpFmt::WithDataHeader3DW
        } else {
            TlpFmt::NoDataHeader3DW
        };
        let type_enc = if self.config_type == 0 {
            TlpFormatEncodingType::ConfigType0Request
        } else {
            TlpFormatEncodingType::ConfigType1Request
        };

        let dw0 = build_dw0(fmt, type_enc, self.length);
        let mut pkt = Vec::from(dw0);

        // DW1: requester_id(16) | tag(8) | last_dw_be(4) | first_dw_be(4)
        pkt.push((self.requester_id >> 8) as u8);
        pkt.push(self.requester_id as u8);
        pkt.push(self.tag);
        pkt.push((self.last_dw_be << 4) | self.first_dw_be);

        // DW2: bus(8) | device(5) | function(3) | rsvd(4) | ext_reg(4) | register(6) | r(2)
        pkt.push(self.bus);
        pkt.push((self.device << 3) | self.function);
        pkt.push((self.ext_reg << 4) | ((self.register >> 4) & 0x03));
        pkt.push((self.register << 2) & 0xFC);

        if let Some(payload) = self.data {
            pkt.extend_from_slice(&payload);
        }

        pkt
    }
}

impl Default for ConfigRequestBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for Completion TLP packets.
///
/// Use `.data()` to make it a Completion with Data.
///
/// # Examples
///
/// ```
/// use rtlp_lib::{CompletionBuilder, TlpPacket, TlpType};
///
/// let bytes = CompletionBuilder::new()
///     .completer_id(0x2001)
///     .requester_id(0x0400)
///     .tag(0xAB)
///     .byte_count(252)
///     .lower_address(0x00)
///     .length(1)
///     .data(vec![0xDE, 0xAD, 0xBE, 0xEF])
///     .build();
///
/// let pkt = TlpPacket::new(bytes).unwrap();
/// assert_eq!(pkt.get_tlp_type().unwrap(), TlpType::CplData);
/// ```
pub struct CompletionBuilder {
    completer_id: u16,
    status: u8,
    bcm: u8,
    byte_count: u16,
    requester_id: u16,
    tag: u8,
    lower_address: u8,
    length: u16,
    locked: bool,
    data: Option<Vec<u8>>,
}

impl CompletionBuilder {
    pub fn new() -> Self {
        CompletionBuilder {
            completer_id: 0,
            status: 0,
            bcm: 0,
            byte_count: 0,
            requester_id: 0,
            tag: 0,
            lower_address: 0,
            length: 0,
            locked: false,
            data: None,
        }
    }

    pub fn completer_id(mut self, id: u16) -> Self {
        self.completer_id = id;
        self
    }
    pub fn status(mut self, stat: u8) -> Self {
        self.status = stat & 0x07;
        self
    }
    pub fn bcm(mut self, bcm: u8) -> Self {
        self.bcm = bcm & 0x01;
        self
    }
    pub fn byte_count(mut self, bc: u16) -> Self {
        self.byte_count = bc & 0xFFF;
        self
    }
    pub fn requester_id(mut self, id: u16) -> Self {
        self.requester_id = id;
        self
    }
    pub fn tag(mut self, tag: u8) -> Self {
        self.tag = tag;
        self
    }
    pub fn lower_address(mut self, la: u8) -> Self {
        self.lower_address = la & 0x7F;
        self
    }
    pub fn length(mut self, len: u16) -> Self {
        self.length = len & 0x3ff;
        self
    }
    pub fn locked(mut self, locked: bool) -> Self {
        self.locked = locked;
        self
    }
    /// Attach completion data payload. Setting data makes this CplD / CplDLk.
    pub fn data(mut self, payload: Vec<u8>) -> Self {
        self.data = Some(payload);
        self
    }

    pub fn build(self) -> Vec<u8> {
        let has_data = self.data.is_some();
        let fmt = if has_data {
            TlpFmt::WithDataHeader3DW
        } else {
            TlpFmt::NoDataHeader3DW
        };
        let type_enc = if self.locked {
            TlpFormatEncodingType::CompletionLocked
        } else {
            TlpFormatEncodingType::Completion
        };

        let dw0 = build_dw0(fmt, type_enc, self.length);
        let mut pkt = Vec::from(dw0);

        // DW1: completer_id(16) | status(3) | bcm(1) | byte_count(12)
        pkt.push((self.completer_id >> 8) as u8);
        pkt.push(self.completer_id as u8);
        let stat_bcm_bc_hi =
            (self.status << 5) | (self.bcm << 4) | ((self.byte_count >> 8) as u8 & 0x0F);
        pkt.push(stat_bcm_bc_hi);
        pkt.push(self.byte_count as u8);

        // DW2: requester_id(16) | tag(8) | R(1) | lower_address(7)
        pkt.push((self.requester_id >> 8) as u8);
        pkt.push(self.requester_id as u8);
        pkt.push(self.tag);
        pkt.push(self.lower_address & 0x7F);

        if let Some(payload) = self.data {
            pkt.extend_from_slice(&payload);
        }

        pkt
    }
}

impl Default for CompletionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for Message TLP packets.
///
/// # Examples
///
/// ```
/// use rtlp_lib::MessageBuilder;
///
/// let bytes = MessageBuilder::new()
///     .requester_id(0xABCD)
///     .tag(0x01)
///     .message_code(0x7F)
///     .build();
///
/// // DW0 byte0: fmt=000 | type=10000 → 0x10 (Msg, NoData3DW)
/// assert_eq!(bytes[0], 0x10);
/// // DW1: req_id, tag, msg_code
/// assert_eq!(&bytes[4..8], &[0xAB, 0xCD, 0x01, 0x7F]);
/// ```
pub struct MessageBuilder {
    requester_id: u16,
    tag: u8,
    message_code: u8,
    dw3: u32,
    dw4: u32,
    length: u16,
    data: Option<Vec<u8>>,
}

impl MessageBuilder {
    pub fn new() -> Self {
        MessageBuilder {
            requester_id: 0,
            tag: 0,
            message_code: 0,
            dw3: 0,
            dw4: 0,
            length: 0,
            data: None,
        }
    }

    pub fn requester_id(mut self, id: u16) -> Self {
        self.requester_id = id;
        self
    }
    pub fn tag(mut self, tag: u8) -> Self {
        self.tag = tag;
        self
    }
    pub fn message_code(mut self, code: u8) -> Self {
        self.message_code = code;
        self
    }
    pub fn dw3(mut self, val: u32) -> Self {
        self.dw3 = val;
        self
    }
    pub fn dw4(mut self, val: u32) -> Self {
        self.dw4 = val;
        self
    }
    pub fn length(mut self, len: u16) -> Self {
        self.length = len & 0x3ff;
        self
    }
    /// Attach message data payload. Setting data makes this MsgD.
    pub fn data(mut self, payload: Vec<u8>) -> Self {
        self.data = Some(payload);
        self
    }

    pub fn build(self) -> Vec<u8> {
        let has_data = self.data.is_some();
        let fmt = if has_data {
            TlpFmt::WithDataHeader3DW
        } else {
            TlpFmt::NoDataHeader3DW
        };

        // Messages use type encoding 10000 (0x10) for routed-to-RC,
        // but the existing TlpFormatEncodingType doesn't cover Message types.
        // Messages have type field bits [4:3] varying by routing.
        // For now, encode directly: fmt(3) | type=10xxx where xxx = routing
        // The simplest: type = 10000 (route to Root Complex) = 0b10000 = 0x10
        let dw0_byte0 = ((fmt as u8 & 0x7) << 5) | 0x10;
        let len = self.length & 0x3ff;
        let dw0 = [
            dw0_byte0,
            0x00,
            ((len >> 8) & 0x3) as u8,
            (len & 0xff) as u8,
        ];
        let mut pkt = Vec::from(dw0);

        // DW1: requester_id(16) | tag(8) | message_code(8)
        pkt.push((self.requester_id >> 8) as u8);
        pkt.push(self.requester_id as u8);
        pkt.push(self.tag);
        pkt.push(self.message_code);

        // DW2: dw3
        pkt.extend_from_slice(&self.dw3.to_be_bytes());

        // DW3: dw4
        pkt.extend_from_slice(&self.dw4.to_be_bytes());

        if let Some(payload) = self.data {
            pkt.extend_from_slice(&payload);
        }

        pkt
    }
}

impl Default for MessageBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for Atomic Operation TLP packets (FetchAdd, Swap, CompareSwap).
///
/// # Examples
///
/// ```
/// use rtlp_lib::{AtomicRequestBuilder, AtomicOp, TlpPacket, TlpType};
///
/// // 32-bit FetchAdd
/// let bytes = AtomicRequestBuilder::new(AtomicOp::FetchAdd)
///     .requester_id(0xDEAD)
///     .tag(0x42)
///     .address(0xC001_0004)
///     .operand0(10)
///     .build();
///
/// let pkt = TlpPacket::new(bytes).unwrap();
/// assert_eq!(pkt.get_tlp_type().unwrap(), TlpType::FetchAddAtomicOpReq);
/// ```
pub struct AtomicRequestBuilder {
    op: AtomicOp,
    requester_id: u16,
    tag: u8,
    address: u64,
    operand0: u64,
    operand1: Option<u64>,
}

impl AtomicRequestBuilder {
    pub fn new(op: AtomicOp) -> Self {
        AtomicRequestBuilder {
            op,
            requester_id: 0,
            tag: 0,
            address: 0,
            operand0: 0,
            operand1: if matches!(op, AtomicOp::CompareSwap) {
                Some(0)
            } else {
                None
            },
        }
    }

    pub fn requester_id(mut self, id: u16) -> Self {
        self.requester_id = id;
        self
    }
    pub fn tag(mut self, tag: u8) -> Self {
        self.tag = tag;
        self
    }
    pub fn address(mut self, addr: u64) -> Self {
        self.address = addr;
        self
    }
    /// Primary operand: addend (FetchAdd), new value (Swap), compare value (CAS).
    pub fn operand0(mut self, val: u64) -> Self {
        self.operand0 = val;
        self
    }
    /// Second operand: swap value for CompareSwap. Ignored for FetchAdd/Swap.
    pub fn operand1(mut self, val: u64) -> Self {
        if matches!(self.op, AtomicOp::CompareSwap) {
            self.operand1 = Some(val);
        }
        self
    }

    pub fn build(self) -> Vec<u8> {
        let is_4dw = self.address > 0xFFFF_FFFF;
        let fmt = if is_4dw {
            TlpFmt::WithDataHeader4DW
        } else {
            TlpFmt::WithDataHeader3DW
        };

        let type_enc = match self.op {
            AtomicOp::FetchAdd => TlpFormatEncodingType::FetchAtomicOpRequest,
            AtomicOp::Swap => TlpFormatEncodingType::UnconSwapAtomicOpRequest,
            AtomicOp::CompareSwap => TlpFormatEncodingType::CompSwapAtomicOpRequest,
        };

        let dw0 = build_dw0(fmt, type_enc, 0);
        let mut pkt = Vec::from(dw0);

        // DW1: requester_id(16) | tag(8) | BE(8)
        pkt.push((self.requester_id >> 8) as u8);
        pkt.push(self.requester_id as u8);
        pkt.push(self.tag);
        pkt.push(0x00); // byte enables

        // Address
        if is_4dw {
            pkt.extend_from_slice(&self.address.to_be_bytes());
        } else {
            pkt.extend_from_slice(&(self.address as u32).to_be_bytes());
        }

        // Operands — width matches address width
        if is_4dw {
            pkt.extend_from_slice(&self.operand0.to_be_bytes());
            if let Some(op1) = self.operand1 {
                pkt.extend_from_slice(&op1.to_be_bytes());
            }
        } else {
            pkt.extend_from_slice(&(self.operand0 as u32).to_be_bytes());
            if let Some(op1) = self.operand1 {
                pkt.extend_from_slice(&(op1 as u32).to_be_bytes());
            }
        }

        pkt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tlp_header_type() {
        // Empty packet is still MemREAD: FMT '000' Type '0 0000' Length 0
        let memread = TlpHeader([0x0, 0x0, 0x0, 0x0]);
        assert_eq!(memread.get_tlp_type().unwrap(), TlpType::MemReadReq);

        // MemRead32 FMT '000' Type '0 0000'
        let memread32 = TlpHeader([0x00, 0x00, 0x20, 0x01]);
        assert_eq!(memread32.get_tlp_type().unwrap(), TlpType::MemReadReq);

        // MemWrite32 FMT '010' Type '0 0000'
        let memwrite32 = TlpHeader([0x40, 0x00, 0x00, 0x01]);
        assert_eq!(memwrite32.get_tlp_type().unwrap(), TlpType::MemWriteReq);

        // CPL without Data: FMT '000' Type '0 1010'
        let cpl_no_data = TlpHeader([0x0a, 0x00, 0x10, 0x00]);
        assert_eq!(cpl_no_data.get_tlp_type().unwrap(), TlpType::Cpl);

        // CPL with Data: FMT '010' Type '0 1010'
        let cpl_with_data = TlpHeader([0x4a, 0x00, 0x20, 0x40]);
        assert_eq!(cpl_with_data.get_tlp_type().unwrap(), TlpType::CplData);

        // MemRead 4DW: FMT: '001' Type '0 0000'
        let memread_4dw = TlpHeader([0x20, 0x00, 0x20, 0x40]);
        assert_eq!(memread_4dw.get_tlp_type().unwrap(), TlpType::MemReadReq);

        // Config Type 0 Read request: FMT: '000' Type '0 0100'
        let conf_t0_read = TlpHeader([0x04, 0x00, 0x00, 0x01]);
        assert_eq!(
            conf_t0_read.get_tlp_type().unwrap(),
            TlpType::ConfType0ReadReq
        );

        // Config Type 0 Write request: FMT: '010' Type '0 0100'
        let conf_t0_write = TlpHeader([0x44, 0x00, 0x00, 0x01]);
        assert_eq!(
            conf_t0_write.get_tlp_type().unwrap(),
            TlpType::ConfType0WriteReq
        );

        // Config Type 1 Read request: FMT: '000' Type '0 0101'
        let conf_t1_read = TlpHeader([0x05, 0x88, 0x80, 0x01]);
        assert_eq!(
            conf_t1_read.get_tlp_type().unwrap(),
            TlpType::ConfType1ReadReq
        );

        // Config Type 1 Write request: FMT: '010' Type '0 0101'
        let conf_t1_write = TlpHeader([0x45, 0x88, 0x80, 0x01]);
        assert_eq!(
            conf_t1_write.get_tlp_type().unwrap(),
            TlpType::ConfType1WriteReq
        );

        // HeaderLog: 04000001 0000220f 01070000 af36fc70
        // HeaderLog: 60009001 4000000f 00000280 4047605c
        let memwrite64 = TlpHeader([0x60, 0x00, 0x90, 0x01]);
        assert_eq!(memwrite64.get_tlp_type().unwrap(), TlpType::MemWriteReq);
    }

    #[test]
    fn tlp_header_works_all_zeros() {
        let bits_locations = TlpHeader([0x0, 0x0, 0x0, 0x0]);

        assert_eq!(bits_locations.get_format(), 0);
        assert_eq!(bits_locations.get_type(), 0);
        assert_eq!(bits_locations.get_t9(), 0);
        assert_eq!(bits_locations.get_tc(), 0);
        assert_eq!(bits_locations.get_t8(), 0);
        assert_eq!(bits_locations.get_attr_b2(), 0);
        assert_eq!(bits_locations.get_ln(), 0);
        assert_eq!(bits_locations.get_th(), 0);
        assert_eq!(bits_locations.get_td(), 0);
        assert_eq!(bits_locations.get_ep(), 0);
        assert_eq!(bits_locations.get_attr(), 0);
        assert_eq!(bits_locations.get_at(), 0);
        assert_eq!(bits_locations.get_length(), 0);
    }

    #[test]
    fn tlp_header_works_all_ones() {
        let bits_locations = TlpHeader([0xff, 0xff, 0xff, 0xff]);

        assert_eq!(bits_locations.get_format(), 0x7);
        assert_eq!(bits_locations.get_type(), 0x1f);
        assert_eq!(bits_locations.get_t9(), 0x1);
        assert_eq!(bits_locations.get_tc(), 0x7);
        assert_eq!(bits_locations.get_t8(), 0x1);
        assert_eq!(bits_locations.get_attr_b2(), 0x1);
        assert_eq!(bits_locations.get_ln(), 0x1);
        assert_eq!(bits_locations.get_th(), 0x1);
        assert_eq!(bits_locations.get_td(), 0x1);
        assert_eq!(bits_locations.get_ep(), 0x1);
        assert_eq!(bits_locations.get_attr(), 0x3);
        assert_eq!(bits_locations.get_at(), 0x3);
        assert_eq!(bits_locations.get_length(), 0x3ff);
    }

    #[test]
    fn test_invalid_format_error() {
        // Format field with invalid value (e.g., 0b101 = 5)
        let invalid_fmt = TlpHeader([0xa0, 0x00, 0x00, 0x01]); // FMT='101' Type='00000'
        let result = invalid_fmt.get_tlp_type();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), TlpError::InvalidFormat);
    }

    #[test]
    fn test_invalid_type_error() {
        // Type field with invalid encoding (e.g., 0b01111 = 15)
        let invalid_type = TlpHeader([0x0f, 0x00, 0x00, 0x01]); // FMT='000' Type='01111'
        let result = invalid_type.get_tlp_type();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), TlpError::InvalidType);
    }

    #[test]
    fn test_unsupported_combination_error() {
        // Valid format and type but unsupported combination
        // IO Request with 4DW header (not valid)
        let invalid_combo = TlpHeader([0x22, 0x00, 0x00, 0x01]); // FMT='001' Type='00010' (IO Request 4DW)
        let result = invalid_combo.get_tlp_type();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), TlpError::UnsupportedCombination);
    }

    // ── constructor format validation ─────────────────────────────────────

    #[test]
    fn conf_req_rejects_4dw_formats() {
        let bytes = vec![0x00; 8];
        assert!(matches!(
            new_conf_req(bytes.clone(), &TlpFmt::NoDataHeader4DW),
            Err(TlpError::UnsupportedCombination)
        ));
        assert!(matches!(
            new_conf_req(bytes.clone(), &TlpFmt::WithDataHeader4DW),
            Err(TlpError::UnsupportedCombination)
        ));
        assert!(matches!(
            new_conf_req(bytes, &TlpFmt::TlpPrefix),
            Err(TlpError::UnsupportedCombination)
        ));
    }

    #[test]
    fn conf_req_accepts_3dw_formats() {
        let bytes = vec![0x00; 8];
        assert!(new_conf_req(bytes.clone(), &TlpFmt::NoDataHeader3DW).is_ok());
        assert!(new_conf_req(bytes, &TlpFmt::WithDataHeader3DW).is_ok());
    }

    #[test]
    fn cmpl_req_rejects_4dw_formats() {
        let bytes = vec![0x00; 8];
        assert!(matches!(
            new_cmpl_req(bytes.clone(), &TlpFmt::NoDataHeader4DW),
            Err(TlpError::UnsupportedCombination)
        ));
        assert!(matches!(
            new_cmpl_req(bytes.clone(), &TlpFmt::WithDataHeader4DW),
            Err(TlpError::UnsupportedCombination)
        ));
        assert!(matches!(
            new_cmpl_req(bytes, &TlpFmt::TlpPrefix),
            Err(TlpError::UnsupportedCombination)
        ));
    }

    #[test]
    fn cmpl_req_accepts_3dw_formats() {
        let bytes = vec![0x00; 8];
        assert!(new_cmpl_req(bytes.clone(), &TlpFmt::NoDataHeader3DW).is_ok());
        assert!(new_cmpl_req(bytes, &TlpFmt::WithDataHeader3DW).is_ok());
    }

    #[test]
    fn msg_req_rejects_tlp_prefix() {
        let bytes = vec![0x00; 12];
        assert!(matches!(
            new_msg_req(bytes, &TlpFmt::TlpPrefix),
            Err(TlpError::UnsupportedCombination)
        ));
    }

    #[test]
    fn msg_req_accepts_all_standard_formats() {
        let bytes = vec![0x00; 12];
        assert!(new_msg_req(bytes.clone(), &TlpFmt::NoDataHeader3DW).is_ok());
        assert!(new_msg_req(bytes.clone(), &TlpFmt::NoDataHeader4DW).is_ok());
        assert!(new_msg_req(bytes.clone(), &TlpFmt::WithDataHeader3DW).is_ok());
        assert!(new_msg_req(bytes, &TlpFmt::WithDataHeader4DW).is_ok());
    }

    // ── new_mem_req rejects TlpPrefix ──────────────────────────────────────

    #[test]
    fn mem_req_rejects_tlp_prefix() {
        let bytes = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let result = new_mem_req(bytes, &TlpFmt::TlpPrefix);
        assert!(matches!(result, Err(TlpError::UnsupportedCombination)));
    }

    // ── short packet rejection ─────────────────────────────────────────────

    #[test]
    fn packet_new_rejects_empty_input() {
        assert!(matches!(
            TlpPacket::new(vec![]),
            Err(TlpError::InvalidLength)
        ));
    }

    #[test]
    fn packet_new_rejects_3_bytes() {
        assert!(matches!(
            TlpPacket::new(vec![0x00, 0x00, 0x00]),
            Err(TlpError::InvalidLength)
        ));
    }

    #[test]
    fn packet_new_accepts_4_bytes() {
        // Exactly 4 bytes = header only, no data — should succeed
        assert!(TlpPacket::new(vec![0x00, 0x00, 0x00, 0x00]).is_ok());
    }

    #[test]
    fn packet_header_new_rejects_short_input() {
        assert!(matches!(
            TlpPacketHeader::new(vec![0x00, 0x00]),
            Err(TlpError::InvalidLength)
        ));
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /// Build a DW0-only TlpHeader from a 3-bit fmt and 5-bit type field.
    /// byte0 layout (MSB0): bits[7:5] = fmt, bits[4:0] = type
    fn dw0(fmt: u8, typ: u8) -> TlpHeader<[u8; 4]> {
        TlpHeader([(fmt << 5) | (typ & 0x1f), 0x00, 0x00, 0x00])
    }

    /// Build a full TLP byte vector: DW0 header + arbitrary payload bytes.
    /// DW0 bytes 1-3 are left 0 (length / TC / flags irrelevant for field tests).
    fn mk_tlp(fmt: u8, typ: u8, rest: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + rest.len());
        v.push((fmt << 5) | (typ & 0x1f));
        v.push(0x00); // TC, T9, T8, Attr_b2, LN, TH
        v.push(0x00); // TD, Ep, Attr, AT
        v.push(0x00); // Length
        v.extend_from_slice(rest);
        v
    }

    // ── happy path: every currently-supported (fmt, type) pair ────────────────

    #[test]
    fn header_decode_supported_pairs() {
        const FMT_3DW_NO_DATA: u8 = 0b000;
        const FMT_4DW_NO_DATA: u8 = 0b001;
        const FMT_3DW_WITH_DATA: u8 = 0b010;
        const FMT_4DW_WITH_DATA: u8 = 0b011;

        const TY_MEM: u8 = 0b00000;
        const TY_MEM_LK: u8 = 0b00001;
        const TY_IO: u8 = 0b00010;
        const TY_CFG0: u8 = 0b00100;
        const TY_CFG1: u8 = 0b00101;
        const TY_CPL: u8 = 0b01010;
        const TY_CPL_LK: u8 = 0b01011;
        const TY_ATOM_FETCH: u8 = 0b01100;
        const TY_ATOM_SWAP: u8 = 0b01101;
        const TY_ATOM_CAS: u8 = 0b01110;
        const TY_DMWR: u8 = 0b11011;

        // Memory Request: NoData → Read, WithData → Write; both 3DW and 4DW
        assert_eq!(
            dw0(FMT_3DW_NO_DATA, TY_MEM).get_tlp_type().unwrap(),
            TlpType::MemReadReq
        );
        assert_eq!(
            dw0(FMT_4DW_NO_DATA, TY_MEM).get_tlp_type().unwrap(),
            TlpType::MemReadReq
        );
        assert_eq!(
            dw0(FMT_3DW_WITH_DATA, TY_MEM).get_tlp_type().unwrap(),
            TlpType::MemWriteReq
        );
        assert_eq!(
            dw0(FMT_4DW_WITH_DATA, TY_MEM).get_tlp_type().unwrap(),
            TlpType::MemWriteReq
        );

        // Memory Lock Request: NoData only (3DW and 4DW)
        assert_eq!(
            dw0(FMT_3DW_NO_DATA, TY_MEM_LK).get_tlp_type().unwrap(),
            TlpType::MemReadLockReq
        );
        assert_eq!(
            dw0(FMT_4DW_NO_DATA, TY_MEM_LK).get_tlp_type().unwrap(),
            TlpType::MemReadLockReq
        );

        // IO Request: 3DW only; NoData → Read, WithData → Write
        assert_eq!(
            dw0(FMT_3DW_NO_DATA, TY_IO).get_tlp_type().unwrap(),
            TlpType::IOReadReq
        );
        assert_eq!(
            dw0(FMT_3DW_WITH_DATA, TY_IO).get_tlp_type().unwrap(),
            TlpType::IOWriteReq
        );

        // Config Type 0: 3DW only
        assert_eq!(
            dw0(FMT_3DW_NO_DATA, TY_CFG0).get_tlp_type().unwrap(),
            TlpType::ConfType0ReadReq
        );
        assert_eq!(
            dw0(FMT_3DW_WITH_DATA, TY_CFG0).get_tlp_type().unwrap(),
            TlpType::ConfType0WriteReq
        );

        // Config Type 1: 3DW only
        assert_eq!(
            dw0(FMT_3DW_NO_DATA, TY_CFG1).get_tlp_type().unwrap(),
            TlpType::ConfType1ReadReq
        );
        assert_eq!(
            dw0(FMT_3DW_WITH_DATA, TY_CFG1).get_tlp_type().unwrap(),
            TlpType::ConfType1WriteReq
        );

        // Completion: 3DW only; NoData → Cpl, WithData → CplData
        assert_eq!(
            dw0(FMT_3DW_NO_DATA, TY_CPL).get_tlp_type().unwrap(),
            TlpType::Cpl
        );
        assert_eq!(
            dw0(FMT_3DW_WITH_DATA, TY_CPL).get_tlp_type().unwrap(),
            TlpType::CplData
        );

        // Completion Locked: 3DW only
        assert_eq!(
            dw0(FMT_3DW_NO_DATA, TY_CPL_LK).get_tlp_type().unwrap(),
            TlpType::CplLocked
        );
        assert_eq!(
            dw0(FMT_3DW_WITH_DATA, TY_CPL_LK).get_tlp_type().unwrap(),
            TlpType::CplDataLocked
        );

        // Atomics: WithData only (3DW and 4DW)
        assert_eq!(
            dw0(FMT_3DW_WITH_DATA, TY_ATOM_FETCH)
                .get_tlp_type()
                .unwrap(),
            TlpType::FetchAddAtomicOpReq
        );
        assert_eq!(
            dw0(FMT_4DW_WITH_DATA, TY_ATOM_FETCH)
                .get_tlp_type()
                .unwrap(),
            TlpType::FetchAddAtomicOpReq
        );

        assert_eq!(
            dw0(FMT_3DW_WITH_DATA, TY_ATOM_SWAP).get_tlp_type().unwrap(),
            TlpType::SwapAtomicOpReq
        );
        assert_eq!(
            dw0(FMT_4DW_WITH_DATA, TY_ATOM_SWAP).get_tlp_type().unwrap(),
            TlpType::SwapAtomicOpReq
        );

        assert_eq!(
            dw0(FMT_3DW_WITH_DATA, TY_ATOM_CAS).get_tlp_type().unwrap(),
            TlpType::CompareSwapAtomicOpReq
        );
        assert_eq!(
            dw0(FMT_4DW_WITH_DATA, TY_ATOM_CAS).get_tlp_type().unwrap(),
            TlpType::CompareSwapAtomicOpReq
        );

        // DMWr: WithData only (3DW and 4DW)
        assert_eq!(
            dw0(FMT_3DW_WITH_DATA, TY_DMWR).get_tlp_type().unwrap(),
            TlpType::DeferrableMemWriteReq
        );
        assert_eq!(
            dw0(FMT_4DW_WITH_DATA, TY_DMWR).get_tlp_type().unwrap(),
            TlpType::DeferrableMemWriteReq
        );
    }

    // ── negative path: every illegal (fmt, type) pair → UnsupportedCombination ─

    #[test]
    fn header_decode_rejects_unsupported_combinations() {
        const FMT_3DW_NO_DATA: u8 = 0b000;
        const FMT_4DW_NO_DATA: u8 = 0b001;
        const FMT_3DW_WITH_DATA: u8 = 0b010;
        const FMT_4DW_WITH_DATA: u8 = 0b011;
        const FMT_PREFIX: u8 = 0b100;

        const TY_MEM_LK: u8 = 0b00001;
        const TY_IO: u8 = 0b00010;
        const TY_CFG0: u8 = 0b00100;
        const TY_CFG1: u8 = 0b00101;
        const TY_CPL: u8 = 0b01010;
        const TY_CPL_LK: u8 = 0b01011;
        const TY_ATOM_FETCH: u8 = 0b01100;
        const TY_ATOM_SWAP: u8 = 0b01101;
        const TY_ATOM_CAS: u8 = 0b01110;
        const TY_DMWR: u8 = 0b11011;

        // IO: 4DW variants are illegal
        assert_eq!(
            dw0(FMT_4DW_NO_DATA, TY_IO).get_tlp_type().unwrap_err(),
            TlpError::UnsupportedCombination
        );
        assert_eq!(
            dw0(FMT_4DW_WITH_DATA, TY_IO).get_tlp_type().unwrap_err(),
            TlpError::UnsupportedCombination
        );

        // Config: 4DW variants are illegal (configs are always 3DW)
        assert_eq!(
            dw0(FMT_4DW_NO_DATA, TY_CFG0).get_tlp_type().unwrap_err(),
            TlpError::UnsupportedCombination
        );
        assert_eq!(
            dw0(FMT_4DW_WITH_DATA, TY_CFG0).get_tlp_type().unwrap_err(),
            TlpError::UnsupportedCombination
        );
        assert_eq!(
            dw0(FMT_4DW_NO_DATA, TY_CFG1).get_tlp_type().unwrap_err(),
            TlpError::UnsupportedCombination
        );
        assert_eq!(
            dw0(FMT_4DW_WITH_DATA, TY_CFG1).get_tlp_type().unwrap_err(),
            TlpError::UnsupportedCombination
        );

        // Completions: 4DW variants are illegal
        assert_eq!(
            dw0(FMT_4DW_NO_DATA, TY_CPL).get_tlp_type().unwrap_err(),
            TlpError::UnsupportedCombination
        );
        assert_eq!(
            dw0(FMT_4DW_WITH_DATA, TY_CPL).get_tlp_type().unwrap_err(),
            TlpError::UnsupportedCombination
        );
        assert_eq!(
            dw0(FMT_4DW_NO_DATA, TY_CPL_LK).get_tlp_type().unwrap_err(),
            TlpError::UnsupportedCombination
        );
        assert_eq!(
            dw0(FMT_4DW_WITH_DATA, TY_CPL_LK)
                .get_tlp_type()
                .unwrap_err(),
            TlpError::UnsupportedCombination
        );

        // Atomics: NoData variants are illegal (atomics always carry data)
        assert_eq!(
            dw0(FMT_3DW_NO_DATA, TY_ATOM_FETCH)
                .get_tlp_type()
                .unwrap_err(),
            TlpError::UnsupportedCombination
        );
        assert_eq!(
            dw0(FMT_4DW_NO_DATA, TY_ATOM_FETCH)
                .get_tlp_type()
                .unwrap_err(),
            TlpError::UnsupportedCombination
        );
        assert_eq!(
            dw0(FMT_3DW_NO_DATA, TY_ATOM_SWAP)
                .get_tlp_type()
                .unwrap_err(),
            TlpError::UnsupportedCombination
        );
        assert_eq!(
            dw0(FMT_4DW_NO_DATA, TY_ATOM_SWAP)
                .get_tlp_type()
                .unwrap_err(),
            TlpError::UnsupportedCombination
        );
        assert_eq!(
            dw0(FMT_3DW_NO_DATA, TY_ATOM_CAS)
                .get_tlp_type()
                .unwrap_err(),
            TlpError::UnsupportedCombination
        );
        assert_eq!(
            dw0(FMT_4DW_NO_DATA, TY_ATOM_CAS)
                .get_tlp_type()
                .unwrap_err(),
            TlpError::UnsupportedCombination
        );

        // MemReadLock: WithData variants are illegal (lock is a read-only operation)
        assert_eq!(
            dw0(FMT_3DW_WITH_DATA, TY_MEM_LK)
                .get_tlp_type()
                .unwrap_err(),
            TlpError::UnsupportedCombination
        );
        assert_eq!(
            dw0(FMT_4DW_WITH_DATA, TY_MEM_LK)
                .get_tlp_type()
                .unwrap_err(),
            TlpError::UnsupportedCombination
        );

        // TlpPrefix fmt (0b100) is a valid format value but illegal for all
        // request/completion type encodings — currently hits UnsupportedCombination
        assert_eq!(
            dw0(FMT_PREFIX, TY_IO).get_tlp_type().unwrap_err(),
            TlpError::UnsupportedCombination
        );
        assert_eq!(
            dw0(FMT_PREFIX, TY_CPL).get_tlp_type().unwrap_err(),
            TlpError::UnsupportedCombination
        );
        assert_eq!(
            dw0(FMT_PREFIX, TY_CFG0).get_tlp_type().unwrap_err(),
            TlpError::UnsupportedCombination
        );

        // DMWr: NoData variants are illegal (DMWr always carries data)
        assert_eq!(
            dw0(FMT_3DW_NO_DATA, TY_DMWR).get_tlp_type().unwrap_err(),
            TlpError::UnsupportedCombination
        );
        assert_eq!(
            dw0(FMT_4DW_NO_DATA, TY_DMWR).get_tlp_type().unwrap_err(),
            TlpError::UnsupportedCombination
        );
        assert_eq!(
            dw0(FMT_PREFIX, TY_DMWR).get_tlp_type().unwrap_err(),
            TlpError::UnsupportedCombination
        );
    }

    // ── DMWr: Deferrable Memory Write header decode ────────────────────────

    #[test]
    fn tlp_header_dmwr32_decode() {
        // Fmt=010 (3DW w/ Data), Type=11011 (DMWr) → byte0 = 0x5B
        let dmwr32 = TlpHeader([0x5B, 0x00, 0x00, 0x00]);
        assert_eq!(
            dmwr32.get_tlp_type().unwrap(),
            TlpType::DeferrableMemWriteReq
        );
    }

    #[test]
    fn tlp_header_dmwr64_decode() {
        // Fmt=011 (4DW w/ Data), Type=11011 (DMWr) → byte0 = 0x7B
        let dmwr64 = TlpHeader([0x7B, 0x00, 0x00, 0x00]);
        assert_eq!(
            dmwr64.get_tlp_type().unwrap(),
            TlpType::DeferrableMemWriteReq
        );
    }

    #[test]
    fn tlp_header_dmwr_rejects_nodata_formats() {
        // Fmt=000, Type=11011 → byte0 = 0x1B
        let dmwr_bad_3dw_nodata = TlpHeader([0x1B, 0x00, 0x00, 0x00]);
        assert_eq!(
            dmwr_bad_3dw_nodata.get_tlp_type().unwrap_err(),
            TlpError::UnsupportedCombination
        );

        // Fmt=001, Type=11011 → byte0 = 0x3B
        let dmwr_bad_4dw_nodata = TlpHeader([0x3B, 0x00, 0x00, 0x00]);
        assert_eq!(
            dmwr_bad_4dw_nodata.get_tlp_type().unwrap_err(),
            TlpError::UnsupportedCombination
        );
    }

    #[test]
    fn dmwr_full_packet_3dw_fields() {
        // DMWr32 through TlpPacket pipeline with MemRequest3DW fields
        let payload = [
            0xAB, 0xCD, 0x42, 0x0F, // req_id=0xABCD, tag=0x42, BE=0x0F
            0xDE, 0xAD, 0x00, 0x00, // address32=0xDEAD0000
        ];
        let pkt = TlpPacket::new(mk_tlp(0b010, 0b11011, &payload)).unwrap();
        assert_eq!(pkt.get_tlp_type().unwrap(), TlpType::DeferrableMemWriteReq);
        assert_eq!(pkt.get_tlp_format().unwrap(), TlpFmt::WithDataHeader3DW);

        let mr = new_mem_req(pkt.get_data(), &pkt.get_tlp_format().unwrap()).unwrap();
        assert_eq!(mr.req_id(), 0xABCD);
        assert_eq!(mr.tag(), 0x42);
        assert_eq!(mr.address(), 0xDEAD_0000);
    }

    #[test]
    fn dmwr_full_packet_4dw_fields() {
        // DMWr64 through TlpPacket pipeline with MemRequest4DW fields
        let payload = [
            0xBE, 0xEF, 0xA5, 0x00, // req_id=0xBEEF, tag=0xA5
            0x11, 0x22, 0x33, 0x44, // address64 hi
            0x55, 0x66, 0x77, 0x88, // address64 lo
        ];
        let pkt = TlpPacket::new(mk_tlp(0b011, 0b11011, &payload)).unwrap();
        assert_eq!(pkt.get_tlp_type().unwrap(), TlpType::DeferrableMemWriteReq);
        assert_eq!(pkt.get_tlp_format().unwrap(), TlpFmt::WithDataHeader4DW);

        let mr = new_mem_req(pkt.get_data(), &pkt.get_tlp_format().unwrap()).unwrap();
        assert_eq!(mr.req_id(), 0xBEEF);
        assert_eq!(mr.tag(), 0xA5);
        assert_eq!(mr.address(), 0x1122_3344_5566_7788);
    }

    // ── is_non_posted() semantics ─────────────────────────────────────────────

    #[test]
    fn is_non_posted_returns_true_for_non_posted_types() {
        assert!(TlpType::MemReadReq.is_non_posted());
        assert!(TlpType::MemReadLockReq.is_non_posted());
        assert!(TlpType::IOReadReq.is_non_posted());
        assert!(TlpType::IOWriteReq.is_non_posted());
        assert!(TlpType::ConfType0ReadReq.is_non_posted());
        assert!(TlpType::ConfType0WriteReq.is_non_posted());
        assert!(TlpType::ConfType1ReadReq.is_non_posted());
        assert!(TlpType::ConfType1WriteReq.is_non_posted());
        assert!(TlpType::FetchAddAtomicOpReq.is_non_posted());
        assert!(TlpType::SwapAtomicOpReq.is_non_posted());
        assert!(TlpType::CompareSwapAtomicOpReq.is_non_posted());
        assert!(TlpType::DeferrableMemWriteReq.is_non_posted());
    }

    #[test]
    fn is_non_posted_returns_false_for_posted_types() {
        assert!(!TlpType::MemWriteReq.is_non_posted());
        assert!(!TlpType::MsgReq.is_non_posted());
        assert!(!TlpType::MsgReqData.is_non_posted());
    }

    #[test]
    fn is_non_posted_returns_false_for_completions() {
        // Completions are responses, not requests — is_non_posted() is false
        assert!(!TlpType::Cpl.is_non_posted());
        assert!(!TlpType::CplData.is_non_posted());
        assert!(!TlpType::CplLocked.is_non_posted());
        assert!(!TlpType::CplDataLocked.is_non_posted());
    }

    // ── atomic tier-A: real bytes through the full packet pipeline ─────────────

    #[test]
    fn atomic_fetchadd_3dw_type_and_fields() {
        const FMT_3DW_WITH_DATA: u8 = 0b010;
        const TY_ATOM_FETCH: u8 = 0b01100;

        // DW1+DW2 as MemRequest3DW sees them (MSB0):
        //   requester_id [15:0]  = 0x1234
        //   tag          [23:16] = 0x56
        //   last_dw_be   [27:24] = 0x0  (ignored for this test)
        //   first_dw_be  [31:28] = 0x0  (ignored for this test)
        //   address32    [63:32] = 0x89ABCDEF
        let payload = [
            0x12, 0x34, // req_id
            0x56, 0x00, // tag, BE nibbles
            0x89, 0xAB, 0xCD, 0xEF, // address32
        ];

        let pkt = TlpPacket::new(mk_tlp(FMT_3DW_WITH_DATA, TY_ATOM_FETCH, &payload)).unwrap();

        assert_eq!(pkt.get_tlp_type().unwrap(), TlpType::FetchAddAtomicOpReq);
        assert_eq!(pkt.get_tlp_format().unwrap(), TlpFmt::WithDataHeader3DW);

        let fmt = pkt.get_tlp_format().unwrap();
        let mr = new_mem_req(pkt.get_data(), &fmt).unwrap();
        assert_eq!(mr.req_id(), 0x1234);
        assert_eq!(mr.tag(), 0x56);
        assert_eq!(mr.address(), 0x89AB_CDEF);
    }

    #[test]
    fn atomic_cas_4dw_type_and_fields() {
        const FMT_4DW_WITH_DATA: u8 = 0b011;
        const TY_ATOM_CAS: u8 = 0b01110;

        // DW1-DW3 as MemRequest4DW sees them (MSB0):
        //   requester_id [15:0]  = 0xBEEF
        //   tag          [23:16] = 0xA5
        //   last/first_dw_be     = 0x00
        //   address64    [95:32] = 0x1122_3344_5566_7788
        let payload = [
            0xBE, 0xEF, // req_id
            0xA5, 0x00, // tag, BE nibbles
            0x11, 0x22, 0x33, 0x44, // address64 high DW
            0x55, 0x66, 0x77, 0x88, // address64 low DW
        ];

        let pkt = TlpPacket::new(mk_tlp(FMT_4DW_WITH_DATA, TY_ATOM_CAS, &payload)).unwrap();

        assert_eq!(pkt.get_tlp_type().unwrap(), TlpType::CompareSwapAtomicOpReq);
        assert_eq!(pkt.get_tlp_format().unwrap(), TlpFmt::WithDataHeader4DW);

        let fmt = pkt.get_tlp_format().unwrap();
        let mr = new_mem_req(pkt.get_data(), &fmt).unwrap();
        assert_eq!(mr.req_id(), 0xBEEF);
        assert_eq!(mr.tag(), 0xA5);
        assert_eq!(mr.address(), 0x1122_3344_5566_7788);
    }

    // ── atomic tier-B: operand parsing via new_atomic_req() ───────────────────

    #[test]
    fn fetchadd_3dw_operand() {
        // FetchAdd 3DW (W32): single 32-bit addend after the 8-byte header
        //   DW1: req_id=0xDEAD  tag=0x42  BE=0x00
        //   DW2: address32=0xC001_0004
        //   op0: addend=0x0000_000A
        let payload = [
            0xDE, 0xAD, 0x42, 0x00, // req_id, tag, BE
            0xC0, 0x01, 0x00, 0x04, // address32
            0x00, 0x00, 0x00, 0x0A, // addend (W32)
        ];
        let pkt = TlpPacket::new(mk_tlp(0b010, 0b01100, &payload)).unwrap();
        let ar = new_atomic_req(&pkt).unwrap();

        assert_eq!(ar.op(), AtomicOp::FetchAdd);
        assert_eq!(ar.width(), AtomicWidth::W32);
        assert_eq!(ar.req_id(), 0xDEAD);
        assert_eq!(ar.tag(), 0x42);
        assert_eq!(ar.address(), 0xC001_0004);
        assert_eq!(ar.operand0(), 0x0A);
        assert!(ar.operand1().is_none());
    }

    #[test]
    fn fetchadd_4dw_operand() {
        // FetchAdd 4DW (W64): single 64-bit addend after the 12-byte header
        //   DW1: req_id=0x0042  tag=0xBB  BE=0x00
        //   DW2-DW3: address64=0x0000_0001_0000_0000
        //   op0: addend=0xFFFF_FFFF_FFFF_FFFF
        let payload = [
            0x00, 0x42, 0xBB, 0x00, // req_id, tag, BE
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // address64
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // addend (W64)
        ];
        let pkt = TlpPacket::new(mk_tlp(0b011, 0b01100, &payload)).unwrap();
        let ar = new_atomic_req(&pkt).unwrap();

        assert_eq!(ar.op(), AtomicOp::FetchAdd);
        assert_eq!(ar.width(), AtomicWidth::W64);
        assert_eq!(ar.req_id(), 0x0042);
        assert_eq!(ar.tag(), 0xBB);
        assert_eq!(ar.address(), 0x0000_0001_0000_0000);
        assert_eq!(ar.operand0(), 0xFFFF_FFFF_FFFF_FFFF);
        assert!(ar.operand1().is_none());
    }

    #[test]
    fn swap_3dw_operand() {
        // Swap 3DW (W32): single 32-bit swap value
        //   DW1: req_id=0x1111  tag=0x05  BE=0x00
        //   DW2: address32=0xF000_0008
        //   op0: new_value=0xABCD_EF01
        let payload = [
            0x11, 0x11, 0x05, 0x00, // req_id, tag, BE
            0xF0, 0x00, 0x00, 0x08, // address32
            0xAB, 0xCD, 0xEF, 0x01, // new_value (W32)
        ];
        let pkt = TlpPacket::new(mk_tlp(0b010, 0b01101, &payload)).unwrap();
        let ar = new_atomic_req(&pkt).unwrap();

        assert_eq!(ar.op(), AtomicOp::Swap);
        assert_eq!(ar.width(), AtomicWidth::W32);
        assert_eq!(ar.req_id(), 0x1111);
        assert_eq!(ar.tag(), 0x05);
        assert_eq!(ar.address(), 0xF000_0008);
        assert_eq!(ar.operand0(), 0xABCD_EF01);
        assert!(ar.operand1().is_none());
    }

    #[test]
    fn cas_3dw_two_operands() {
        // CAS 3DW (W32): compare then swap — two 32-bit operands
        //   DW1: req_id=0xABCD  tag=0x07  BE=0x00
        //   DW2: address32=0x0000_4000
        //   op0: compare=0xCAFE_BABE
        //   op1: swap=0xDEAD_BEEF
        let payload = [
            0xAB, 0xCD, 0x07, 0x00, // req_id, tag, BE
            0x00, 0x00, 0x40, 0x00, // address32
            0xCA, 0xFE, 0xBA, 0xBE, // compare (W32)
            0xDE, 0xAD, 0xBE, 0xEF, // swap    (W32)
        ];
        let pkt = TlpPacket::new(mk_tlp(0b010, 0b01110, &payload)).unwrap();
        let ar = new_atomic_req(&pkt).unwrap();

        assert_eq!(ar.op(), AtomicOp::CompareSwap);
        assert_eq!(ar.width(), AtomicWidth::W32);
        assert_eq!(ar.req_id(), 0xABCD);
        assert_eq!(ar.tag(), 0x07);
        assert_eq!(ar.address(), 0x0000_4000);
        assert_eq!(ar.operand0(), 0xCAFE_BABE);
        assert_eq!(ar.operand1(), Some(0xDEAD_BEEF));
    }

    #[test]
    fn cas_4dw_two_operands() {
        // CAS 4DW (W64): compare then swap — two 64-bit operands
        //   DW1: req_id=0x1234  tag=0xAA  BE=0x00
        //   DW2-DW3: address64=0xFFFF_FFFF_0000_0000
        //   op0: compare=0x0101_0101_0202_0202
        //   op1: swap=0x0303_0303_0404_0404
        let payload = [
            0x12, 0x34, 0xAA, 0x00, // req_id, tag, BE
            0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, // address64
            0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, // compare (W64)
            0x03, 0x03, 0x03, 0x03, 0x04, 0x04, 0x04, 0x04, // swap    (W64)
        ];
        let pkt = TlpPacket::new(mk_tlp(0b011, 0b01110, &payload)).unwrap();
        let ar = new_atomic_req(&pkt).unwrap();

        assert_eq!(ar.op(), AtomicOp::CompareSwap);
        assert_eq!(ar.width(), AtomicWidth::W64);
        assert_eq!(ar.req_id(), 0x1234);
        assert_eq!(ar.tag(), 0xAA);
        assert_eq!(ar.address(), 0xFFFF_FFFF_0000_0000);
        assert_eq!(ar.operand0(), 0x0101_0101_0202_0202);
        assert_eq!(ar.operand1(), Some(0x0303_0303_0404_0404));
    }

    #[test]
    fn atomic_req_rejects_wrong_tlp_type() {
        // MemRead type is not an atomic — should get UnsupportedCombination
        let pkt = TlpPacket::new(mk_tlp(0b000, 0b00000, &[0u8; 16])).unwrap();
        assert_eq!(
            new_atomic_req(&pkt).err().unwrap(),
            TlpError::UnsupportedCombination
        );
    }

    #[test]
    fn atomic_req_rejects_wrong_format() {
        // FetchAdd type with NoData3DW format is an invalid combo:
        // get_tlp_type() returns UnsupportedCombination, which propagates
        let pkt = TlpPacket::new(mk_tlp(0b000, 0b01100, &[0u8; 16])).unwrap();
        assert_eq!(
            new_atomic_req(&pkt).err().unwrap(),
            TlpError::UnsupportedCombination
        );
    }

    #[test]
    fn atomic_req_rejects_short_payload() {
        // 3 bytes data — FetchAdd 3DW needs exactly 12 (8 hdr + 4 operand)
        let pkt = TlpPacket::new(mk_tlp(0b010, 0b01100, &[0u8; 3])).unwrap();
        assert_eq!(new_atomic_req(&pkt).err().unwrap(), TlpError::InvalidLength);

        // 8 bytes data — header OK but operand missing (needs 12)
        let pkt = TlpPacket::new(mk_tlp(0b010, 0b01100, &[0u8; 8])).unwrap();
        assert_eq!(new_atomic_req(&pkt).err().unwrap(), TlpError::InvalidLength);

        // 20 bytes data — CAS 4DW needs exactly 28 (12 hdr + 8 + 8)
        let pkt = TlpPacket::new(mk_tlp(0b011, 0b01110, &[0u8; 20])).unwrap();
        assert_eq!(new_atomic_req(&pkt).err().unwrap(), TlpError::InvalidLength);
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    fn mk_pkt(fmt: u8, typ: u8, data: &[u8]) -> TlpPacket {
        TlpPacket::new(mk_tlp(fmt, typ, data)).unwrap()
    }

    // ── atomic tier-B (new API): real binary layout, single-argument call ─────

    #[test]
    fn atomic_fetchadd_3dw_32_parses_operands() {
        // FetchAdd 3DW (W32): 8-byte header + 4-byte addend
        let data = [
            0x01, 0x00, 0x01, 0x00, // req_id=0x0100, tag=0x01, BE=0x00
            0x00, 0x00, 0x10, 0x00, // address32=0x0000_1000
            0x00, 0x00, 0x00, 0x07, // addend=7
        ];
        let pkt = mk_pkt(0b010, 0b01100, &data);
        let a = new_atomic_req(&pkt).unwrap();
        assert_eq!(a.op(), AtomicOp::FetchAdd);
        assert_eq!(a.width(), AtomicWidth::W32);
        assert_eq!(a.req_id(), 0x0100);
        assert_eq!(a.tag(), 0x01);
        assert_eq!(a.address(), 0x0000_1000);
        assert_eq!(a.operand0(), 7);
        assert!(a.operand1().is_none());
    }

    #[test]
    fn atomic_swap_4dw_64_parses_operands() {
        // Swap 4DW (W64): 12-byte header + 8-byte new value
        let data = [
            0xBE, 0xEF, 0xA5, 0x00, // req_id=0xBEEF, tag=0xA5, BE=0x00
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // address64=0x0000_0001_0000_0000
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, // new_value
        ];
        let pkt = mk_pkt(0b011, 0b01101, &data);
        let a = new_atomic_req(&pkt).unwrap();
        assert_eq!(a.op(), AtomicOp::Swap);
        assert_eq!(a.width(), AtomicWidth::W64);
        assert_eq!(a.req_id(), 0xBEEF);
        assert_eq!(a.tag(), 0xA5);
        assert_eq!(a.address(), 0x0000_0001_0000_0000);
        assert_eq!(a.operand0(), 0xDEAD_BEEF_CAFE_BABE);
        assert!(a.operand1().is_none());
    }

    #[test]
    fn atomic_cas_3dw_32_parses_operands() {
        // CAS 3DW (W32): 8-byte header + 4-byte compare + 4-byte swap
        let data = [
            0xAB, 0xCD, 0x07, 0x00, // req_id=0xABCD, tag=0x07, BE=0x00
            0x00, 0x00, 0x40, 0x00, // address32=0x0000_4000
            0xCA, 0xFE, 0xBA, 0xBE, // compare
            0xDE, 0xAD, 0xBE, 0xEF, // swap
        ];
        let pkt = mk_pkt(0b010, 0b01110, &data);
        let a = new_atomic_req(&pkt).unwrap();
        assert_eq!(a.op(), AtomicOp::CompareSwap);
        assert_eq!(a.width(), AtomicWidth::W32);
        assert_eq!(a.req_id(), 0xABCD);
        assert_eq!(a.tag(), 0x07);
        assert_eq!(a.address(), 0x0000_4000);
        assert_eq!(a.operand0(), 0xCAFE_BABE);
        assert_eq!(a.operand1(), Some(0xDEAD_BEEF));
    }

    // ── CompletionReqDW23: Lower Address 7-bit decode ──────────────────────

    #[test]
    fn completion_laddr_full_7_bits() {
        // Lower Address = 0x7F (127) — all 7 bits set
        // DW2 byte 3: R(1 bit)=0, LowerAddr(7 bits)=0x7F → byte = 0x7F
        let bytes = vec![
            0x00, 0x00, 0x00, 0x00, // completer_id, cmpl_stat, bcm, byte_cnt
            0x00, 0x00, 0x00, 0x7F, // req_id, tag, R=0, laddr=0x7F
        ];
        let cmpl = new_cmpl_req(bytes, &TlpFmt::NoDataHeader3DW).unwrap();
        assert_eq!(cmpl.laddr(), 0x7F);
    }

    #[test]
    fn completion_laddr_bit6_set() {
        // Lower Address = 64 (0x40) — bit 6 is the bit that was previously lost
        // DW2 byte 3: R=0, LowerAddr=0x40 → byte = 0x40
        let bytes = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40];
        let cmpl = new_cmpl_req(bytes, &TlpFmt::NoDataHeader3DW).unwrap();
        assert_eq!(cmpl.laddr(), 0x40);
    }

    #[test]
    fn completion_laddr_with_reserved_bit_set() {
        // R=1, LowerAddr=0x55 (85)
        // DW2 byte 3: 1_1010101 = 0xD5
        let bytes = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD5];
        let cmpl = new_cmpl_req(bytes, &TlpFmt::NoDataHeader3DW).unwrap();
        assert_eq!(cmpl.laddr(), 0x55);
    }

    #[test]
    fn completion_full_fields_with_laddr() {
        // completer_id=0x2001, cmpl_stat=0, bcm=0, byte_cnt=0x0FC,
        // req_id=0x1234, tag=0xAB, R=0, laddr=100 (0x64)
        let bytes = vec![
            0x20, 0x01, 0x00, 0xFC, // completer_id=0x2001, status=0, bcm=0, byte_cnt=0x0FC
            0x12, 0x34, 0xAB, 0x64, // req_id=0x1234, tag=0xAB, R=0, laddr=0x64
        ];
        let cmpl = new_cmpl_req(bytes, &TlpFmt::NoDataHeader3DW).unwrap();
        assert_eq!(cmpl.cmpl_id(), 0x2001);
        assert_eq!(cmpl.byte_cnt(), 0x0FC);
        assert_eq!(cmpl.req_id(), 0x1234);
        assert_eq!(cmpl.tag(), 0xAB);
        assert_eq!(cmpl.laddr(), 0x64);
    }

    #[test]
    fn atomic_fetchadd_rejects_invalid_operand_length() {
        // FetchAdd 3DW expects exactly 12 bytes (8 hdr + 4 operand).
        // A 14-byte payload (8 hdr + 6-byte "bad" operand) must be rejected.
        let bad = [
            0x01, 0x00, 0x01, 0x00, // req_id, tag, BE
            0x00, 0x00, 0x10, 0x00, // address32
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 6 bytes instead of 4
        ];
        let pkt = mk_pkt(0b010, 0b01100, &bad);
        assert_eq!(new_atomic_req(&pkt).unwrap_err(), TlpError::InvalidLength);
    }

    // ── MessageReqDW24: DW3/DW4 full 32-bit decode ───────────────────────────

    #[test]
    fn message_dw3_preserves_upper_16_bits() {
        // DW3 = 0xDEAD_BEEF — upper 16 bits (0xDEAD) must survive
        let bytes = vec![
            0x00, 0x00, 0x00, 0x00, // req_id, tag, msg_code
            0xDE, 0xAD, 0xBE, 0xEF, // DW3
            0x00, 0x00, 0x00, 0x00, // DW4
        ];
        let msg = new_msg_req(bytes, &TlpFmt::NoDataHeader3DW).unwrap();
        assert_eq!(msg.dw3(), 0xDEAD_BEEF);
    }

    #[test]
    fn message_dw4_preserves_upper_16_bits() {
        // DW4 = 0xCAFE_BABE — upper 16 bits (0xCAFE) must survive
        let bytes = vec![
            0x00, 0x00, 0x00, 0x00, // req_id, tag, msg_code
            0x00, 0x00, 0x00, 0x00, // DW3
            0xCA, 0xFE, 0xBA, 0xBE, // DW4
        ];
        let msg = new_msg_req(bytes, &TlpFmt::NoDataHeader3DW).unwrap();
        assert_eq!(msg.dw4(), 0xCAFE_BABE);
    }

    #[test]
    fn message_dw3_dw4_all_bits_set() {
        // Both DW3 and DW4 = 0xFFFF_FFFF
        let bytes = vec![
            0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ];
        let msg = new_msg_req(bytes, &TlpFmt::NoDataHeader3DW).unwrap();
        assert_eq!(msg.dw3(), 0xFFFF_FFFF);
        assert_eq!(msg.dw4(), 0xFFFF_FFFF);
    }

    #[test]
    fn message_request_full_fields() {
        // req_id=0xABCD, tag=0x42, msg_code=0x7F, DW3=0x1234_5678, DW4=0x9ABC_DEF0
        let bytes = vec![
            0xAB, 0xCD, 0x42, 0x7F, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
        ];
        let msg = new_msg_req(bytes, &TlpFmt::NoDataHeader3DW).unwrap();
        assert_eq!(msg.req_id(), 0xABCD);
        assert_eq!(msg.tag(), 0x42);
        assert_eq!(msg.msg_code(), 0x7F);
        assert_eq!(msg.dw3(), 0x1234_5678);
        assert_eq!(msg.dw4(), 0x9ABC_DEF0);
    }

    // ── Encoder / Builder tests ──────────────────────────────────────────────

    // ── Memory Request Builder ───────────────────────────────────────────────

    #[test]
    fn encode_memread_32bit() {
        let bytes = MemRequestBuilder::new()
            .requester_id(0x0400)
            .tag(0x20)
            .address(0xF620_000C)
            .first_dw_be(0x0F)
            .length(1)
            .build();

        let pkt = TlpPacket::new(bytes).unwrap();
        assert_eq!(pkt.get_tlp_type().unwrap(), TlpType::MemReadReq);
        assert_eq!(pkt.get_tlp_format().unwrap(), TlpFmt::NoDataHeader3DW);

        let mr = new_mem_req(pkt.get_data(), &pkt.get_tlp_format().unwrap()).unwrap();
        assert_eq!(mr.req_id(), 0x0400);
        assert_eq!(mr.tag(), 0x20);
        assert_eq!(mr.address(), 0xF620_000C);
        assert_eq!(mr.fdwbe(), 0x0F);
    }

    #[test]
    fn encode_memread_64bit() {
        let bytes = MemRequestBuilder::new()
            .requester_id(0xBEEF)
            .tag(0xA5)
            .address(0x1_0000_0000)
            .length(4)
            .build();

        let pkt = TlpPacket::new(bytes).unwrap();
        assert_eq!(pkt.get_tlp_type().unwrap(), TlpType::MemReadReq);
        assert_eq!(pkt.get_tlp_format().unwrap(), TlpFmt::NoDataHeader4DW);

        let mr = new_mem_req(pkt.get_data(), &pkt.get_tlp_format().unwrap()).unwrap();
        assert_eq!(mr.req_id(), 0xBEEF);
        assert_eq!(mr.tag(), 0xA5);
        assert_eq!(mr.address(), 0x1_0000_0000);
    }

    #[test]
    fn encode_memwrite_32bit() {
        let payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let bytes = MemRequestBuilder::new()
            .requester_id(0x1234)
            .tag(0x01)
            .address(0x8000_0000)
            .first_dw_be(0x0F)
            .length(1)
            .data(payload.clone())
            .build();

        let pkt = TlpPacket::new(bytes).unwrap();
        assert_eq!(pkt.get_tlp_type().unwrap(), TlpType::MemWriteReq);
        assert_eq!(pkt.get_tlp_format().unwrap(), TlpFmt::WithDataHeader3DW);

        let data = pkt.get_data();
        // Last 4 bytes should be the payload
        assert_eq!(&data[data.len() - 4..], &payload[..]);
    }

    #[test]
    fn encode_memwrite_64bit() {
        let bytes = MemRequestBuilder::new()
            .requester_id(0xFFFF)
            .address(0xDEAD_BEEF_0000_0000)
            .length(1)
            .data(vec![0x11, 0x22, 0x33, 0x44])
            .build();

        let pkt = TlpPacket::new(bytes).unwrap();
        assert_eq!(pkt.get_tlp_type().unwrap(), TlpType::MemWriteReq);
        assert_eq!(pkt.get_tlp_format().unwrap(), TlpFmt::WithDataHeader4DW);
    }

    // ── Config Request Builder ───────────────────────────────────────────────

    #[test]
    fn encode_config_type0_read() {
        let bytes = ConfigRequestBuilder::new()
            .requester_id(0x0100)
            .tag(0x01)
            .bus(0x02)
            .device(0x03)
            .function(0x01)
            .register(0x10)
            .length(1)
            .build();

        let pkt = TlpPacket::new(bytes).unwrap();
        assert_eq!(pkt.get_tlp_type().unwrap(), TlpType::ConfType0ReadReq);

        let cr = new_conf_req(pkt.get_data(), &pkt.get_tlp_format().unwrap()).unwrap();
        assert_eq!(cr.req_id(), 0x0100);
        assert_eq!(cr.tag(), 0x01);
        assert_eq!(cr.bus_nr(), 0x02);
        assert_eq!(cr.dev_nr(), 0x03);
        assert_eq!(cr.func_nr(), 0x01);
        assert_eq!(cr.reg_nr(), 0x10);
    }

    #[test]
    fn encode_config_type1_write() {
        let bytes = ConfigRequestBuilder::new()
            .requester_id(0x0200)
            .config_type(1)
            .bus(0x05)
            .device(0x1F)
            .register(0x3C)
            .length(1)
            .data(vec![0x00, 0x00, 0x01, 0x00])
            .build();

        let pkt = TlpPacket::new(bytes).unwrap();
        assert_eq!(pkt.get_tlp_type().unwrap(), TlpType::ConfType1WriteReq);
        assert_eq!(pkt.get_tlp_format().unwrap(), TlpFmt::WithDataHeader3DW);
    }

    // ── Completion Builder ───────────────────────────────────────────────────

    #[test]
    fn encode_completion_no_data() {
        let bytes = CompletionBuilder::new()
            .completer_id(0x2001)
            .requester_id(0x0400)
            .tag(0xAB)
            .status(0)
            .byte_count(0)
            .length(0)
            .build();

        let pkt = TlpPacket::new(bytes).unwrap();
        assert_eq!(pkt.get_tlp_type().unwrap(), TlpType::Cpl);
    }

    #[test]
    fn encode_completion_with_data() {
        let bytes = CompletionBuilder::new()
            .completer_id(0x2001)
            .requester_id(0x0400)
            .tag(0xAB)
            .byte_count(252)
            .lower_address(0x00)
            .length(1)
            .data(vec![0xDE, 0xAD, 0xBE, 0xEF])
            .build();

        let pkt = TlpPacket::new(bytes).unwrap();
        assert_eq!(pkt.get_tlp_type().unwrap(), TlpType::CplData);

        let cpl = new_cmpl_req(pkt.get_data(), &pkt.get_tlp_format().unwrap()).unwrap();
        assert_eq!(cpl.cmpl_id(), 0x2001);
        assert_eq!(cpl.req_id(), 0x0400);
        assert_eq!(cpl.tag(), 0xAB);
        assert_eq!(cpl.byte_cnt(), 252);
        assert_eq!(cpl.cmpl_stat(), 0);
    }

    #[test]
    fn encode_completion_locked() {
        let bytes = CompletionBuilder::new()
            .completer_id(0x1000)
            .requester_id(0x2000)
            .locked(true)
            .build();

        let pkt = TlpPacket::new(bytes).unwrap();
        assert_eq!(pkt.get_tlp_type().unwrap(), TlpType::CplLocked);
    }

    // ── Message Builder ──────────────────────────────────────────────────────

    #[test]
    fn encode_message_no_data() {
        // Note: Message type decoding is not yet implemented in get_tlp_type(),
        // so we verify the raw byte layout directly.
        let bytes = MessageBuilder::new()
            .requester_id(0xABCD)
            .tag(0x01)
            .message_code(0x7F)
            .build();

        // DW0 byte0: fmt=000 | type=10000 → 0x10 (Msg, NoData3DW)
        assert_eq!(bytes[0], 0x10);
        // DW1: req_id=0xABCD, tag=0x01, msg_code=0x7F
        assert_eq!(&bytes[4..8], &[0xAB, 0xCD, 0x01, 0x7F]);
        // Total: 4 (DW0) + 4 (DW1) + 4 (DW2/dw3) + 4 (DW3/dw4) = 16 bytes
        assert_eq!(bytes.len(), 16);
    }

    #[test]
    fn encode_message_with_data() {
        let bytes = MessageBuilder::new()
            .requester_id(0x1234)
            .message_code(0x42)
            .length(1)
            .data(vec![0x11, 0x22, 0x33, 0x44])
            .build();

        // DW0 byte0: fmt=010 | type=10000 → 0x50 (MsgD, WithData3DW)
        assert_eq!(bytes[0], 0x50);
        // Payload appended at end
        assert_eq!(&bytes[bytes.len() - 4..], &[0x11, 0x22, 0x33, 0x44]);
    }

    #[test]
    fn encode_message_dw3_dw4() {
        let bytes = MessageBuilder::new()
            .requester_id(0x0000)
            .dw3(0xCAFE_BABE)
            .dw4(0xDEAD_BEEF)
            .build();

        // DW2 (dw3) at offset 8, DW3 (dw4) at offset 12
        assert_eq!(&bytes[8..12], &0xCAFE_BABEu32.to_be_bytes());
        assert_eq!(&bytes[12..16], &0xDEAD_BEEFu32.to_be_bytes());
    }

    // ── Atomic Request Builder ───────────────────────────────────────────────

    #[test]
    fn encode_fetchadd_32bit() {
        let bytes = AtomicRequestBuilder::new(AtomicOp::FetchAdd)
            .requester_id(0xDEAD)
            .tag(0x42)
            .address(0xC001_0004)
            .operand0(10)
            .build();

        let pkt = TlpPacket::new(bytes).unwrap();
        assert_eq!(pkt.get_tlp_type().unwrap(), TlpType::FetchAddAtomicOpReq);

        let ar = new_atomic_req(&pkt).unwrap();
        assert_eq!(ar.req_id(), 0xDEAD);
        assert_eq!(ar.tag(), 0x42);
        assert_eq!(ar.address(), 0xC001_0004);
        assert_eq!(ar.operand0(), 10);
        assert!(ar.operand1().is_none());
    }

    #[test]
    fn encode_swap_64bit() {
        let bytes = AtomicRequestBuilder::new(AtomicOp::Swap)
            .requester_id(0xBEEF)
            .tag(0xA5)
            .address(0x1_0000_0000)
            .operand0(0xDEAD_BEEF_CAFE_BABE)
            .build();

        let pkt = TlpPacket::new(bytes).unwrap();
        assert_eq!(pkt.get_tlp_type().unwrap(), TlpType::SwapAtomicOpReq);
        assert_eq!(pkt.get_tlp_format().unwrap(), TlpFmt::WithDataHeader4DW);

        let ar = new_atomic_req(&pkt).unwrap();
        assert_eq!(ar.operand0(), 0xDEAD_BEEF_CAFE_BABE);
        assert!(ar.operand1().is_none());
    }

    #[test]
    fn encode_cas_32bit() {
        let bytes = AtomicRequestBuilder::new(AtomicOp::CompareSwap)
            .requester_id(0xABCD)
            .tag(0x07)
            .address(0x4000)
            .operand0(0xCAFE_BABE)
            .operand1(0xDEAD_BEEF)
            .build();

        let pkt = TlpPacket::new(bytes).unwrap();
        assert_eq!(pkt.get_tlp_type().unwrap(), TlpType::CompareSwapAtomicOpReq);

        let ar = new_atomic_req(&pkt).unwrap();
        assert_eq!(ar.req_id(), 0xABCD);
        assert_eq!(ar.tag(), 0x07);
        assert_eq!(ar.address(), 0x4000);
        assert_eq!(ar.operand0(), 0xCAFE_BABE);
        assert_eq!(ar.operand1(), Some(0xDEAD_BEEF));
    }

    #[test]
    fn encode_cas_64bit() {
        let bytes = AtomicRequestBuilder::new(AtomicOp::CompareSwap)
            .requester_id(0x1234)
            .tag(0xAA)
            .address(0xFFFF_FFFF_0000_0000)
            .operand0(0x0101_0101_0202_0202)
            .operand1(0x0303_0303_0404_0404)
            .build();

        let pkt = TlpPacket::new(bytes).unwrap();
        let ar = new_atomic_req(&pkt).unwrap();
        assert_eq!(ar.width(), AtomicWidth::W64);
        assert_eq!(ar.operand0(), 0x0101_0101_0202_0202);
        assert_eq!(ar.operand1(), Some(0x0303_0303_0404_0404));
    }

    // ── Round-trip: encode → decode → verify ─────────────────────────────────

    #[test]
    fn roundtrip_memread_32() {
        let bytes = MemRequestBuilder::new()
            .requester_id(0x0400)
            .tag(0x20)
            .address(0xF620_000C)
            .first_dw_be(0x0F)
            .length(1)
            .build();

        let pkt = TlpPacket::new(bytes.clone()).unwrap();
        let mr = new_mem_req(pkt.get_data(), &pkt.get_tlp_format().unwrap()).unwrap();

        // Re-encode from decoded values
        let bytes2 = MemRequestBuilder::new()
            .requester_id(mr.req_id())
            .tag(mr.tag())
            .address(mr.address())
            .first_dw_be(mr.fdwbe())
            .last_dw_be(mr.ldwbe())
            .length(pkt.get_header().get_length() as u16)
            .build();

        assert_eq!(bytes, bytes2);
    }

    #[test]
    fn roundtrip_completion_data() {
        let bytes = CompletionBuilder::new()
            .completer_id(0x2001)
            .requester_id(0x0400)
            .tag(0xAB)
            .byte_count(252)
            .lower_address(0x3C)
            .length(1)
            .data(vec![0xDE, 0xAD, 0xBE, 0xEF])
            .build();

        let pkt = TlpPacket::new(bytes.clone()).unwrap();
        let cpl = new_cmpl_req(pkt.get_data(), &pkt.get_tlp_format().unwrap()).unwrap();

        let bytes2 = CompletionBuilder::new()
            .completer_id(cpl.cmpl_id())
            .requester_id(cpl.req_id())
            .tag(cpl.tag())
            .status(cpl.cmpl_stat())
            .bcm(cpl.bcm())
            .byte_count(cpl.byte_cnt())
            .lower_address(cpl.laddr())
            .length(pkt.get_header().get_length() as u16)
            .data(pkt.get_data()[8..].to_vec())
            .build();

        assert_eq!(bytes, bytes2);
    }

    #[test]
    fn roundtrip_atomic_fetchadd() {
        let bytes = AtomicRequestBuilder::new(AtomicOp::FetchAdd)
            .requester_id(0xDEAD)
            .tag(0x42)
            .address(0xC001_0004)
            .operand0(0x0A)
            .build();

        let pkt = TlpPacket::new(bytes.clone()).unwrap();
        let ar = new_atomic_req(&pkt).unwrap();

        let bytes2 = AtomicRequestBuilder::new(ar.op())
            .requester_id(ar.req_id())
            .tag(ar.tag())
            .address(ar.address())
            .operand0(ar.operand0())
            .build();

        assert_eq!(bytes, bytes2);
    }
}
