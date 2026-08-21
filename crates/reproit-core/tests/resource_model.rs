use std::{collections::BTreeMap, str::FromStr as _};

use proptest::prelude::*;
use reproit_core::{
    ErrorCode,
    identity::{Digest, ServiceId},
    model::ProviderResourceClaim,
    resource_model::{
        ProviderCapacity, ProviderReservationModel, ProviderServiceCapacity, ReservationResult,
    },
};

const MAXIMUM: u64 = 64;

proptest! {
    #[test]
    fn reservations_never_exceed_service_or_environment_capacity(
        requests in prop::collection::vec((any::<bool>(), 1_u64..=16), 0..128)
    ) {
        let services = [service(0xabf), service(0xac0)];
        let mut model = ProviderReservationModel::new(capacity(&services)).unwrap();
        let mut admitted = [0_u64; 2];
        for (index, (second_service, amount)) in requests.into_iter().enumerate() {
            let service_index = usize::from(second_service);
            let id = Digest::of(&index.to_be_bytes());
            let result = model.reserve(id, services[service_index], claim(amount));
            if admitted[service_index] + amount <= 32
                && admitted[0] + admitted[1] + amount <= MAXIMUM
            {
                prop_assert_eq!(result, Ok(ReservationResult::Reserved));
                admitted[service_index] += amount;
            } else {
                prop_assert_eq!(result.unwrap_err().code, ErrorCode::RuntimeQuota);
            }
            prop_assert!(model.usage_for_service(services[service_index]).unwrap().pinned_bytes <= 32);
        }
    }
}

#[test]
fn reservation_is_idempotent_and_scope_bound_then_releases() {
    let services = [service(0xabf), service(0xac0)];
    let mut model = ProviderReservationModel::new(capacity(&services)).unwrap();
    let id = Digest::of(b"lease");
    assert_eq!(
        model.reserve(id, services[0], claim(8)).unwrap(),
        ReservationResult::Reserved
    );
    assert_eq!(
        model.reserve(id, services[0], claim(8)).unwrap(),
        ReservationResult::AlreadyReserved
    );
    assert_eq!(
        model.reserve(id, services[1], claim(8)).unwrap_err().code,
        ErrorCode::SchemaInvalid
    );
    assert_eq!(
        model.release(id, services[1]).unwrap_err().code,
        ErrorCode::SchemaInvalid
    );
    model.release(id, services[0]).unwrap();
    assert_eq!(model.active_leases(), 0);
}

fn capacity(services: &[ServiceId; 2]) -> ProviderCapacity {
    ProviderCapacity {
        maximum_active_leases: 64,
        maximum_resource_claim: claim(MAXIMUM),
        service_shares: BTreeMap::from([
            (
                services[0],
                ProviderServiceCapacity {
                    maximum_active_leases: 32,
                    maximum_resource_claim: claim(32),
                },
            ),
            (
                services[1],
                ProviderServiceCapacity {
                    maximum_active_leases: 32,
                    maximum_resource_claim: claim(32),
                },
            ),
        ]),
    }
}

fn claim(amount: u64) -> ProviderResourceClaim {
    ProviderResourceClaim {
        materialized_bytes: amount,
        objects: amount,
        pinned_bytes: amount,
        temporary_bytes: amount,
    }
}

fn service(suffix: u16) -> ServiceId {
    ServiceId::from_str(&format!("svc_01890f3e-7b1c-7cc0-8a1b-{suffix:012x}")).unwrap()
}
