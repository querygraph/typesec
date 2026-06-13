use std::marker::PhantomData;
use std::time::SystemTime;

use typesec_core::{
    resource::GenericResource, Capability, CapabilityRevocationList, CanRead, RevocationEpoch,
};

fn main() {
    let _cap: Capability<CanRead, GenericResource> = Capability {
        id: unsafe { std::mem::zeroed() },
        subject: "agent:forged".to_string(),
        resource_id: "reports/q1".to_string(),
        issued_at: SystemTime::now(),
        expires_at: SystemTime::now(),
        revocation: None::<(RevocationEpoch, u64)>,
        revocation_list: None::<std::sync::Arc<CapabilityRevocationList>>,
        _permission: PhantomData,
        _resource: PhantomData,
    };
}
