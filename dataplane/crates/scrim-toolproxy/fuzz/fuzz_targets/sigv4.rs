//! AWS SigV4 parsing, verification, re-signing and chunk re-signing on arbitrary input.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    scrim_toolproxy::sigv4_testing::fuzz_one(data);
});
