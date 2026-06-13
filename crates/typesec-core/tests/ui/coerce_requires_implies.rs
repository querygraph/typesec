use typesec_core::{resource::GenericResource, CanRead, CanWrite, Capability};

fn escalate(cap: Capability<CanRead, GenericResource>) -> Capability<CanWrite, GenericResource> {
    cap.coerce()
}

fn main() {}
