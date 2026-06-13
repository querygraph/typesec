use typesec_core::Permission;

struct EvilPermission;

impl Permission for EvilPermission {
    fn name() -> &'static str {
        "evil"
    }
}

fn main() {}
