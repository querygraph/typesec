use std::marker::PhantomData;
use std::time::SystemTime;

use typesec_core::{resource::GenericResource, Capability, CanRead, RevocationEpoch};

fn main() {
    let _cap: Capability<CanRead, GenericResource> = Capability {
        subject: "agent:forged".to_string(),
        resource_id: "reports/q1".to_string(),
        issued_at: SystemTime::now(),
        expires_at: SystemTime::now(),
        revocation: None::<(RevocationEpoch, u64)>,
        _permission: PhantomData,
        _resource: PhantomData,
    };
}
