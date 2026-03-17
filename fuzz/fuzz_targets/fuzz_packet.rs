#![no_main]

use libfuzzer_sys::fuzz_target;
use rtlp_lib::*;

fuzz_target!(|data: &[u8]| {
    // Test both framing modes — neither must ever panic
    for &mode in &[TlpMode::NonFlit, TlpMode::Flit] {
        let pkt = match TlpPacket::new(data.to_vec(), mode) {
            Ok(p) => p,
            Err(_) => continue,
        };

        // mode() must not panic
        let _ = pkt.mode();

        // Type/format/flit queries must not panic
        let _ = pkt.tlp_type();
        let _ = pkt.tlp_format();
        let _ = pkt.flit_type();

        // Debug impls must not panic (exercises all pub(crate) header fields internally)
        let _ = format!("{:?}", pkt);
        let _ = format!("{:?}", pkt.header());

        // payload access must not panic
        let _ = pkt.data();

        // get_tc() is the only pub bitfield accessor on TlpPacketHeader
        let _ = pkt.header().get_tc();
    }

    // TlpPacketHeader::new (non-flit only — Flit returns NotImplemented)
    if data.len() >= 4 {
        let _ = TlpPacketHeader::new(data[..4].to_vec(), TlpMode::NonFlit);
        let _ = TlpPacketHeader::new(data[..4].to_vec(), TlpMode::Flit);
    }
});
