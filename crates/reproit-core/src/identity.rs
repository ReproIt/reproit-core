use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use sha2::{Digest as _, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::{Error, error::ErrorCode};

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Digest([u8; 32]);

impl Digest {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "sha256:{}", hex::encode(self.0))
    }
}

impl FromStr for Digest {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let hex_value = value
            .strip_prefix("sha256:")
            .filter(|part| part.len() == 64)
            .ok_or_else(Error::schema_invalid)?;
        if !hex_value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(Error::schema_invalid());
        }
        let mut bytes = [0_u8; 32];
        hex::decode_to_slice(hex_value, &mut bytes).map_err(|_| Error::schema_invalid())?;
        Ok(Self(bytes))
    }
}

impl Serialize for Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(de::Error::custom)
    }
}

macro_rules! typed_id {
    ($name:ident, $prefix:literal) => {
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Uuid);

        impl $name {
            pub const fn as_uuid(&self) -> &Uuid {
                &self.0
            }

            pub const fn uuid_bytes(&self) -> [u8; 16] {
                *self.0.as_bytes()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(self, formatter)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, concat!($prefix, "{}"), self.0)
            }
        }

        impl FromStr for $name {
            type Err = Error;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                let uuid_text = value
                    .strip_prefix($prefix)
                    .ok_or_else(Error::schema_invalid)?;
                let uuid = Uuid::parse_str(uuid_text).map_err(|_| Error::schema_invalid())?;
                if uuid.get_version_num() != 7 || uuid.to_string() != uuid_text {
                    return Err(Error::schema_invalid());
                }
                Ok(Self(uuid))
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                value.parse().map_err(de::Error::custom)
            }
        }
    };
}

typed_id!(OrganizationId, "org_");
typed_id!(ProjectId, "prj_");
typed_id!(ServiceId, "svc_");
typed_id!(CaptureId, "cap_");
typed_id!(OperationId, "op_");
typed_id!(OccurrenceId, "occ_");
typed_id!(ReproId, "rpr_");
typed_id!(UploadId, "upl_");
typed_id!(ObjectId, "obj_");
typed_id!(ExecutionId, "exe_");
typed_id!(LeaseId, "lse_");
typed_id!(DeletionId, "del_");
typed_id!(FuzzCampaignId, "fc_");
typed_id!(FuzzCaseId, "case_");

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Timestamp(String);

impl Timestamp {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Timestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for Timestamp {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if !timestamp_shape_is_valid(value) || OffsetDateTime::parse(value, &Rfc3339).is_err() {
            return Err(Error::schema_invalid());
        }
        Ok(Self(value.to_owned()))
    }
}

impl Serialize for Timestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}

fn timestamp_shape_is_valid(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 24
        && matches!(bytes[4], b'-')
        && matches!(bytes[7], b'-')
        && matches!(bytes[10], b'T')
        && matches!(bytes[13], b':')
        && matches!(bytes[16], b':')
        && matches!(bytes[19], b'.')
        && matches!(bytes[23], b'Z')
        && bytes.iter().enumerate().all(|(index, byte)| {
            matches!(index, 4 | 7 | 10 | 13 | 16 | 19 | 23) || byte.is_ascii_digit()
        })
}

pub fn require_equal_digest(actual: Digest, expected: Digest) -> Result<(), Error> {
    if actual == expected {
        return Ok(());
    }
    Err(Error::new(
        ErrorCode::ObjectDigestMismatch,
        "The object digest does not match its content.",
    ))
}
