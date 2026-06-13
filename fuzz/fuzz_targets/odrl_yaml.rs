#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(yaml) = std::str::from_utf8(data) {
        let _ = typesec_odrl::model::OdrlDocument::from_yaml(yaml);
        let _ = typesec_odrl::OdrlEngine::from_yaml(yaml);
    }
});
