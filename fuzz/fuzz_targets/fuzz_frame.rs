#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| h3x::fuzzing::frame(data));
