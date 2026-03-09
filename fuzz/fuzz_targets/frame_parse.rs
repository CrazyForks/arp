#![no_main]
use arp_common::frame::Frame;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Frame::parse must never panic on arbitrary input
    if let Ok(frame) = Frame::parse(data) {
        // Roundtrip: serialize then parse again should yield equivalent frame
        let serialized = frame.serialize();
        let reparsed = Frame::parse(&serialized).expect("roundtrip parse failed on valid frame");
        // Verify serialized output matches
        assert_eq!(
            serialized,
            reparsed.serialize(),
            "double roundtrip produced different bytes"
        );
    }
});
