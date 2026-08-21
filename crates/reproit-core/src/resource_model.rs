use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    Error,
    identity::{Digest, ServiceId},
    model::{ProviderResourceClaim, Validate},
};

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderServiceCapacity {
    pub maximum_active_leases: u64,
    pub maximum_resource_claim: ProviderResourceClaim,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCapacity {
    pub maximum_active_leases: u64,
    pub maximum_resource_claim: ProviderResourceClaim,
    pub service_shares: BTreeMap<ServiceId, ProviderServiceCapacity>,
}

impl ProviderCapacity {
    pub fn validate(&self) -> Result<(), Error> {
        validate_capacity(self.maximum_active_leases, &self.maximum_resource_claim)?;
        if self.service_shares.is_empty() || self.service_shares.len() > 10_000 {
            return Err(Error::schema_invalid());
        }
        for share in self.service_shares.values() {
            validate_capacity(share.maximum_active_leases, &share.maximum_resource_claim)?;
            if share.maximum_active_leases > self.maximum_active_leases
                || !claim_fits(&share.maximum_resource_claim, &self.maximum_resource_claim)
            {
                return Err(Error::schema_invalid());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ReservationResult {
    Reserved,
    AlreadyReserved,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ActiveReservation {
    claim: ProviderResourceClaim,
    service_id: ServiceId,
}

#[derive(Debug, Clone)]
pub struct ProviderReservationModel {
    active: BTreeMap<Digest, ActiveReservation>,
    capacity: ProviderCapacity,
}

impl ProviderReservationModel {
    pub fn new(capacity: ProviderCapacity) -> Result<Self, Error> {
        capacity.validate()?;
        Ok(Self {
            active: BTreeMap::new(),
            capacity,
        })
    }

    pub fn reserve(
        &mut self,
        reservation_id: Digest,
        service_id: ServiceId,
        claim: ProviderResourceClaim,
    ) -> Result<ReservationResult, Error> {
        claim.validate()?;
        if let Some(active) = self.active.get(&reservation_id) {
            return if active.service_id == service_id && active.claim == claim {
                Ok(ReservationResult::AlreadyReserved)
            } else {
                Err(Error::schema_invalid())
            };
        }
        let service_capacity = self
            .capacity
            .service_shares
            .get(&service_id)
            .ok_or_else(quota)?;
        let environment_usage = usage(self.active.values())?;
        let service_usage = usage(
            self.active
                .values()
                .filter(|active| active.service_id == service_id),
        )?;
        require_available(
            &environment_usage,
            &claim,
            self.capacity.maximum_active_leases,
            &self.capacity.maximum_resource_claim,
        )?;
        require_available(
            &service_usage,
            &claim,
            service_capacity.maximum_active_leases,
            &service_capacity.maximum_resource_claim,
        )?;
        self.active
            .insert(reservation_id, ActiveReservation { claim, service_id });
        Ok(ReservationResult::Reserved)
    }

    pub fn release(&mut self, reservation_id: Digest, service_id: ServiceId) -> Result<(), Error> {
        let active = self
            .active
            .get(&reservation_id)
            .ok_or_else(Error::schema_invalid)?;
        if active.service_id != service_id {
            return Err(Error::schema_invalid());
        }
        self.active.remove(&reservation_id);
        Ok(())
    }

    pub fn active_leases(&self) -> usize {
        self.active.len()
    }

    pub fn usage_for_service(&self, service_id: ServiceId) -> Result<ProviderResourceClaim, Error> {
        usage(
            self.active
                .values()
                .filter(|active| active.service_id == service_id),
        )
        .map(|usage| usage.claim)
    }
}

struct Usage {
    claim: ProviderResourceClaim,
    leases: u64,
}

fn usage<'a>(active: impl Iterator<Item = &'a ActiveReservation>) -> Result<Usage, Error> {
    let mut usage = Usage {
        claim: ProviderResourceClaim {
            materialized_bytes: 0,
            objects: 0,
            pinned_bytes: 0,
            temporary_bytes: 0,
        },
        leases: 0,
    };
    for reservation in active {
        usage.leases = usage.leases.checked_add(1).ok_or_else(quota)?;
        usage.claim = add_claim(&usage.claim, &reservation.claim)?;
    }
    Ok(usage)
}

fn require_available(
    usage: &Usage,
    requested: &ProviderResourceClaim,
    maximum_leases: u64,
    maximum_claim: &ProviderResourceClaim,
) -> Result<(), Error> {
    let next_claim = add_claim(&usage.claim, requested)?;
    if usage.leases >= maximum_leases || !claim_fits(&next_claim, maximum_claim) {
        return Err(quota());
    }
    Ok(())
}

fn add_claim(
    left: &ProviderResourceClaim,
    right: &ProviderResourceClaim,
) -> Result<ProviderResourceClaim, Error> {
    Ok(ProviderResourceClaim {
        materialized_bytes: left
            .materialized_bytes
            .checked_add(right.materialized_bytes)
            .ok_or_else(quota)?,
        objects: left.objects.checked_add(right.objects).ok_or_else(quota)?,
        pinned_bytes: left
            .pinned_bytes
            .checked_add(right.pinned_bytes)
            .ok_or_else(quota)?,
        temporary_bytes: left
            .temporary_bytes
            .checked_add(right.temporary_bytes)
            .ok_or_else(quota)?,
    })
}

fn claim_fits(claim: &ProviderResourceClaim, maximum: &ProviderResourceClaim) -> bool {
    claim.materialized_bytes <= maximum.materialized_bytes
        && claim.objects <= maximum.objects
        && claim.pinned_bytes <= maximum.pinned_bytes
        && claim.temporary_bytes <= maximum.temporary_bytes
}

fn validate_capacity(
    maximum_active_leases: u64,
    maximum_resource_claim: &ProviderResourceClaim,
) -> Result<(), Error> {
    maximum_resource_claim.validate()?;
    if maximum_active_leases == 0 || maximum_active_leases > 1_024 {
        return Err(Error::schema_invalid());
    }
    Ok(())
}

fn quota() -> Error {
    Error::new(
        crate::ErrorCode::RuntimeQuota,
        "The provider resource reservation is full.",
    )
}
