use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize, de, de::IntoDeserializer as _};
use serde_json::{Map, Value};

use crate::{Error, identity::Digest};

const MAX_EXACT_INTEGER: i128 = 9_007_199_254_740_991;

pub fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    let encoded = serde_json::to_vec(value).map_err(|_| Error::schema_invalid())?;
    let strict = parse_strict_value(&encoded)?;
    serde_json_canonicalizer::to_vec(&strict).map_err(|_| Error::schema_invalid())
}

pub fn digest<T: Serialize>(value: &T) -> Result<Digest, Error> {
    canonical_bytes(value).map(|bytes| Digest::of(&bytes))
}

pub fn digest_value(value: &Value) -> Result<Digest, Error> {
    digest(value)
}

pub fn parse_strict<T>(input: &[u8]) -> Result<T, Error>
where
    T: for<'de> Deserialize<'de>,
{
    serde_path_to_error::deserialize(parse_strict_value(input)?.into_deserializer())
        .map_err(|_| Error::schema_invalid())
}

fn parse_strict_value(input: &[u8]) -> Result<Value, Error> {
    validate_number_tokens(input)?;
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let strict =
        StrictValue::deserialize(&mut deserializer).map_err(|_| Error::schema_invalid())?;
    deserializer.end().map_err(|_| Error::schema_invalid())?;
    Ok(strict.0)
}

fn validate_number_tokens(input: &[u8]) -> Result<(), Error> {
    let mut index = 0;
    let mut in_string = false;
    while index < input.len() {
        match input[index] {
            b'"' => {
                in_string = !in_string;
                index += 1;
            }
            b'\\' if in_string => index = index.saturating_add(2),
            byte if !in_string && (byte == b'-' || byte.is_ascii_digit()) => {
                index = validate_number_at(input, index)?;
            }
            _ => index += 1,
        }
    }
    Ok(())
}

fn validate_number_at(input: &[u8], start: usize) -> Result<usize, Error> {
    let mut end = start + 1;
    while end < input.len() && matches!(input[end], b'0'..=b'9' | b'+' | b'-' | b'.' | b'e' | b'E')
    {
        end += 1;
    }
    let token = std::str::from_utf8(&input[start..end]).map_err(|_| Error::schema_invalid())?;
    if token == "-0" || token.bytes().any(|byte| matches!(byte, b'.' | b'e' | b'E')) {
        return Err(Error::schema_invalid());
    }
    let integer = token.parse::<i128>().map_err(|_| Error::schema_invalid())?;
    if !(-MAX_EXACT_INTEGER..=MAX_EXACT_INTEGER).contains(&integer) {
        return Err(Error::schema_invalid());
    }
    Ok(end)
}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> de::Visitor<'de> for StrictValueVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a strict JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if i128::from(value).abs() > MAX_EXACT_INTEGER {
            return Err(E::custom("integer outside the exact range"));
        }
        Ok(StrictValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if i128::from(value) > MAX_EXACT_INTEGER {
            return Err(E::custom("integer outside the exact range"));
        }
        Ok(StrictValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom("floating-point values are not permitted"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictValue>()? {
            values.push(value.0);
        }
        Ok(StrictValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: de::MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while let Some(key) = object.next_key::<String>()? {
            let value = object.next_value::<StrictValue>()?;
            if values.insert(key, value.0).is_some() {
                return Err(de::Error::custom("duplicate object key"));
            }
        }
        Ok(StrictValue(Value::Object(Map::from_iter(values))))
    }
}
