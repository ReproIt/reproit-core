//! Canonical Linux processor capture rule.
//!
//! The pinned contract is `specs/v1/processor-capture.json`. Every SDK and
//! the replay-host observation derive the same sorted capability list from
//! the same host. This module is pure: callers supply the raw `/proc` bytes
//! and the auxiliary-vector value, so the derivation stays deterministic and
//! testable. Capture maps raw views through curated tables and never removes
//! a captured value. A parse failure captures nothing, because static
//! capture may only add information.

use super::{ArmProcessorIdentity, ProcessorArchitecture, ProcessorIdentity, X86ProcessorIdentity};

pub const PROCESSOR_FEATURE_PREFIX: &str = "processor.feature.";
pub const PROCESSOR_OS_STATE_PREFIX: &str = "processor.os-state.";
pub const PROCESSOR_IDENTITY_PREFIX: &str = "processor.identity.";

/// Curated x86 cpuinfo flag to feature-group table. The kernel hides
/// features the operating system did not enable, so the flags line is the
/// process-visible view.
const X86_FLAG_GROUPS: [(&str, &str); 16] = [
    ("aes", "AES"),
    ("avx", "AVX"),
    ("avx2", "AVX2"),
    ("avx512bw", "AVX512BW"),
    ("avx512dq", "AVX512DQ"),
    ("avx512f", "AVX512F"),
    ("avx512vl", "AVX512VL"),
    ("bmi1", "BMI1"),
    ("bmi2", "BMI2"),
    ("fma", "FMA"),
    ("pclmulqdq", "PCLMULQDQ"),
    ("pni", "SSE3"),
    ("sse2", "SSE2"),
    ("sse4_1", "SSE4_1"),
    ("sse4_2", "SSE4_2"),
    ("ssse3", "SSSE3"),
];

/// Curated arm64 `AT_HWCAP` bit to feature-group table.
const ARM64_HWCAP_GROUPS: [(u32, &str); 5] = [
    (1, "ASIMD"),
    (3, "AES"),
    (6, "SHA2"),
    (7, "CRC32"),
    (22, "SVE"),
];

const AT_HWCAP: u64 = 16;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ProcessorCapture {
    pub architecture: ProcessorArchitecture,
    /// Sorted unique `processor.*` capability strings.
    pub capabilities: Vec<String>,
}

pub const fn processor_capture_abi(architecture: ProcessorArchitecture) -> &'static str {
    match architecture {
        ProcessorArchitecture::Arm64 => "aapcs64-linux-gnu",
        ProcessorArchitecture::X86_64 => "sysv-x86-64",
    }
}

/// Derive the capability list for one Linux host from its raw views.
/// `hwcap` is `AT_HWCAP`, `None` when the auxiliary vector was unreadable.
pub fn capture_processor_capabilities(
    architecture: ProcessorArchitecture,
    cpuinfo: &str,
    hwcap: Option<u64>,
) -> ProcessorCapture {
    let mut capabilities = Vec::new();
    match architecture {
        ProcessorArchitecture::X86_64 => {
            let flags = x86_flags(cpuinfo);
            for (flag, group) in X86_FLAG_GROUPS {
                if flags.contains(&flag) {
                    capabilities.push(format!(
                        "{PROCESSOR_FEATURE_PREFIX}{}",
                        capability_suffix(group)
                    ));
                }
            }
            if flags.contains(&"osxsave") {
                capabilities.push(format!("{PROCESSOR_OS_STATE_PREFIX}osxsave"));
            }
            if flags.contains(&"avx") {
                capabilities.push(format!("{PROCESSOR_OS_STATE_PREFIX}xcr0.avx"));
            }
            if flags.contains(&"avx512f") {
                capabilities.push(format!("{PROCESSOR_OS_STATE_PREFIX}xcr0.avx512"));
            }
        }
        ProcessorArchitecture::Arm64 => {
            if let Some(hwcap) = hwcap {
                for (bit, group) in ARM64_HWCAP_GROUPS {
                    if hwcap & (1_u64 << bit) != 0 {
                        capabilities.push(format!(
                            "{PROCESSOR_FEATURE_PREFIX}{}",
                            capability_suffix(group)
                        ));
                    }
                }
                capabilities.push(format!("{PROCESSOR_OS_STATE_PREFIX}auxv.hwcaps"));
            }
        }
    }
    if let Some(token) = identity_token(architecture, cpuinfo) {
        capabilities.push(format!("{PROCESSOR_IDENTITY_PREFIX}{token}"));
    }
    capabilities.sort();
    capabilities.dedup();
    ProcessorCapture {
        architecture,
        capabilities,
    }
}

/// Extract `AT_HWCAP` from raw `/proc/self/auxv` bytes: little-endian
/// 16-byte entries of key then value, terminated by a zero key.
pub fn parse_auxv_hwcap(auxv: &[u8]) -> Option<u64> {
    for entry in auxv.chunks_exact(16) {
        let key = u64::from_le_bytes(entry[..8].try_into().ok()?);
        if key == 0 {
            return None;
        }
        if key == AT_HWCAP {
            return Some(u64::from_le_bytes(entry[8..].try_into().ok()?));
        }
    }
    None
}

/// The complete curated os-enabled-state vocabulary across architectures.
const OS_ENABLED_STATES: [&str; 4] = ["auxv.hwcaps", "osxsave", "xcr0.avx", "xcr0.avx512"];

/// Whether one capability string is a valid SDK-captured processor
/// capability: a curated feature group, a curated os-enabled state, or one
/// well-formed identity token. Anything else, including a
/// `processor.requirement.*` digest that only sealing may bind, is not a
/// capture and fails this check.
pub fn valid_captured_processor_capability(value: &str) -> bool {
    if let Some(suffix) = value.strip_prefix(PROCESSOR_FEATURE_PREFIX) {
        return X86_FLAG_GROUPS
            .iter()
            .map(|(_, group)| group)
            .chain(ARM64_HWCAP_GROUPS.iter().map(|(_, group)| group))
            .any(|group| capability_suffix(group) == suffix);
    }
    if let Some(state) = value.strip_prefix(PROCESSOR_OS_STATE_PREFIX) {
        return OS_ENABLED_STATES.contains(&state);
    }
    if let Some(token) = value.strip_prefix(PROCESSOR_IDENTITY_PREFIX) {
        return decode_identity_token(token).is_some();
    }
    false
}

/// Encode the canonical identity token from `/proc/cpuinfo`, or `None` when
/// a field is missing, malformed, or disagrees between processor blocks.
/// The lowercase token is the canonical captured form.
pub fn identity_token(architecture: ProcessorArchitecture, cpuinfo: &str) -> Option<String> {
    let field_names: &[&str] = match architecture {
        ProcessorArchitecture::X86_64 => {
            &["vendor_id", "cpu family", "model", "stepping", "microcode"]
        }
        ProcessorArchitecture::Arm64 => {
            &["CPU implementer", "CPU variant", "CPU part", "CPU revision"]
        }
    };
    let blocks = identity_blocks(cpuinfo, field_names)?;
    let first = blocks.first()?;
    if blocks.iter().any(|block| block != first) {
        return None;
    }
    let values = first
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect::<Vec<_>>();
    if values
        .iter()
        .any(|value| !value.bytes().all(valid_identity_byte))
    {
        return None;
    }
    match architecture {
        ProcessorArchitecture::X86_64 => {
            for numeric in &values[1..4] {
                numeric.parse::<u32>().ok()?;
            }
            Some(format!(
                "x86.{}.{}.{}.{}.{}",
                values[0], values[1], values[2], values[3], values[4]
            ))
        }
        ProcessorArchitecture::Arm64 => Some(format!(
            "arm.{}.{}.{}.{}",
            values[0], values[1], values[2], values[3]
        )),
    }
}

/// Encode one structured identity as its canonical
/// `processor.identity.<token>` suffix. Capture, the requirement capability
/// list, and replay-host evidence all name an identity with this one form, so
/// the reduction contract can compare them directly.
/// `specs/v1/processor-capture.json` pins the shape.
pub fn encode_identity_token(identity: &ProcessorIdentity) -> String {
    match identity {
        ProcessorIdentity::Arm(arm) => format!(
            "arm.{}.{}.{}.{}",
            arm.implementer, arm.variant, arm.part, arm.revision
        ),
        ProcessorIdentity::X86(x86) => format!(
            "x86.{}.{}.{}.{}.{}",
            x86.vendor, x86.family, x86.model, x86.stepping, x86.microcode
        ),
    }
}

/// Decode a `processor.identity.<token>` capability back to the structured
/// identity. This is the exact inverse of `identity_token` over canonical
/// lowercase captured values.
pub fn decode_identity_token(token: &str) -> Option<ProcessorIdentity> {
    let segments = token.split('.').collect::<Vec<_>>();
    match segments.as_slice() {
        ["x86", vendor, family, model, stepping, microcode] => {
            let identity = X86ProcessorIdentity {
                family: family.parse().ok()?,
                microcode: (*microcode).to_owned(),
                model: model.parse().ok()?,
                stepping: stepping.parse().ok()?,
                vendor: (*vendor).to_owned(),
            };
            valid_identity_value(&identity.vendor)?;
            valid_identity_value(&identity.microcode)?;
            Some(ProcessorIdentity::X86(identity))
        }
        ["arm", implementer, variant, part, revision] => {
            let identity = ArmProcessorIdentity {
                implementer: (*implementer).to_owned(),
                part: (*part).to_owned(),
                revision: (*revision).to_owned(),
                variant: (*variant).to_owned(),
            };
            for value in [
                &identity.implementer,
                &identity.part,
                &identity.revision,
                &identity.variant,
            ] {
                valid_identity_value(value)?;
            }
            Some(ProcessorIdentity::Arm(identity))
        }
        _ => None,
    }
}

/// A curated group name maps to its capability suffix by ASCII lowercasing
/// and mapping underscore to hyphen. The inverse uppercases and maps hyphen
/// back to underscore.
pub fn capability_suffix(group: &str) -> String {
    group
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' => byte.to_ascii_lowercase(),
            b'_' => b'-',
            other => other,
        })
        .map(char::from)
        .collect()
}

fn valid_identity_value(value: &str) -> Option<()> {
    (!value.is_empty() && value.len() <= 64 && value.bytes().all(valid_identity_byte)).then_some(())
}

fn valid_identity_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
}

fn x86_flags(cpuinfo: &str) -> Vec<&str> {
    cpuinfo
        .lines()
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim().eq("flags").then_some(value)
        })
        .flat_map(str::split_whitespace)
        .collect()
}

/// Collect one identity tuple per processor block. Field order follows
/// `field_names`. A block missing any field yields `None` for the whole
/// capture, because a partial identity cannot be canonical.
fn identity_blocks<'a>(cpuinfo: &'a str, field_names: &[&str]) -> Option<Vec<Vec<&'a str>>> {
    let mut blocks = Vec::new();
    for block in cpuinfo
        .split("\n\n")
        .filter(|block| !block.trim().is_empty())
    {
        let mut values = Vec::with_capacity(field_names.len());
        for field in field_names {
            let value = block.lines().find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.trim().eq(*field).then(|| value.trim())
            })?;
            if value.is_empty() {
                return None;
            }
            values.push(value);
        }
        blocks.push(values);
    }
    if blocks.is_empty() {
        None
    } else {
        Some(blocks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vectors() -> serde_json::Value {
        serde_json::from_str(include_str!("../../../../specs/v1/processor-capture.json")).unwrap()
    }

    #[test]
    fn capture_matches_every_pinned_vector() {
        let vectors = vectors();
        for vector in vectors["capture_vectors"].as_array().unwrap() {
            let architecture = match vector["architecture"].as_str().unwrap() {
                "architecture.arm64" => ProcessorArchitecture::Arm64,
                "architecture.x86-64" => ProcessorArchitecture::X86_64,
                other => panic!("unknown architecture {other}"),
            };
            let cpuinfo = vector["cpuinfo"].as_str().unwrap();
            let hwcap = vector["hwcap"].as_u64();
            let capture = capture_processor_capabilities(architecture, cpuinfo, hwcap);
            let expected = vector["expected_capabilities"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap().to_owned())
                .collect::<Vec<_>>();
            assert_eq!(capture.capabilities, expected, "{}", vector["name"]);
        }
    }

    #[test]
    fn the_curated_tables_match_the_pinned_contract() {
        let vectors = vectors();
        let flags = vectors["x86_64"]["cpuinfo_flag_groups"]
            .as_object()
            .unwrap();
        assert_eq!(flags.len(), X86_FLAG_GROUPS.len());
        for (flag, group) in X86_FLAG_GROUPS {
            assert_eq!(flags[flag].as_str().unwrap(), group);
        }
        let bits = vectors["arm64"]["hwcap_bit_groups"].as_object().unwrap();
        assert_eq!(bits.len(), ARM64_HWCAP_GROUPS.len());
        for (bit, group) in ARM64_HWCAP_GROUPS {
            assert_eq!(bits[&bit.to_string()].as_str().unwrap(), group);
        }
        assert_eq!(
            vectors["x86_64"]["abi"].as_str().unwrap(),
            processor_capture_abi(ProcessorArchitecture::X86_64)
        );
        assert_eq!(
            vectors["arm64"]["abi"].as_str().unwrap(),
            processor_capture_abi(ProcessorArchitecture::Arm64)
        );
    }

    #[test]
    fn auxv_parsing_reads_hwcap_and_stops_at_the_terminator() {
        let mut auxv = Vec::new();
        auxv.extend_from_slice(&6_u64.to_le_bytes());
        auxv.extend_from_slice(&4096_u64.to_le_bytes());
        auxv.extend_from_slice(&16_u64.to_le_bytes());
        auxv.extend_from_slice(&0b1010_u64.to_le_bytes());
        auxv.extend_from_slice(&0_u64.to_le_bytes());
        auxv.extend_from_slice(&0_u64.to_le_bytes());
        assert_eq!(parse_auxv_hwcap(&auxv), Some(0b1010));
        assert_eq!(parse_auxv_hwcap(&auxv[..16]), None);
        assert_eq!(parse_auxv_hwcap(&[]), None);
        assert_eq!(parse_auxv_hwcap(&[1, 2, 3]), None);
    }

    #[test]
    fn a_retained_identity_uses_the_captured_capability_form() {
        // Admission compares a retained identity against the sealed captured
        // capability set. A second encoding on either side makes every
        // identity-retaining reduction unadmissible.
        for vector in vectors()["capture_vectors"].as_array().unwrap() {
            let architecture = match vector["architecture"].as_str().unwrap() {
                "architecture.arm64" => ProcessorArchitecture::Arm64,
                _ => ProcessorArchitecture::X86_64,
            };
            let captured = vector["expected_capabilities"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|value| value.as_str())
                .find_map(|value| value.strip_prefix(PROCESSOR_IDENTITY_PREFIX));
            let Some(token) = captured else {
                continue;
            };
            let identity = decode_identity_token(token).unwrap();
            assert_eq!(encode_identity_token(&identity), token);

            let requirement = super::super::ProcessorRequirement {
                abi: processor_capture_abi(architecture).to_owned(),
                architecture,
                format: super::super::ProcessorRequirementFormat::V1,
                identity: Some(identity),
                instruction_features: Vec::new(),
                os_enabled_states: Vec::new(),
            };
            let capabilities =
                super::super::processor_requirement_capabilities(&requirement).unwrap();
            assert!(
                capabilities.contains(&format!("{PROCESSOR_IDENTITY_PREFIX}{token}")),
                "the requirement capability does not use the captured identity form"
            );
        }
    }

    #[test]
    fn identity_tokens_round_trip_through_the_decoder() {
        let x86 = identity_token(
            ProcessorArchitecture::X86_64,
            "vendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t: 143\nstepping\t: 8\nmicrocode\t: 0x2b000643\n",
        )
        .unwrap();
        assert_eq!(x86, "x86.genuineintel.6.143.8.0x2b000643");
        let decoded = decode_identity_token(&x86).unwrap();
        assert_eq!(
            decoded,
            ProcessorIdentity::X86(X86ProcessorIdentity {
                family: 6,
                microcode: "0x2b000643".to_owned(),
                model: 143,
                stepping: 8,
                vendor: "genuineintel".to_owned(),
            })
        );
        let arm = identity_token(
            ProcessorArchitecture::Arm64,
            "CPU implementer\t: 0x41\nCPU variant\t: 0x0\nCPU part\t: 0xd0c\nCPU revision\t: 1\n",
        )
        .unwrap();
        assert_eq!(arm, "arm.0x41.0x0.0xd0c.1");
        assert_eq!(
            decode_identity_token(&arm).unwrap(),
            ProcessorIdentity::Arm(ArmProcessorIdentity {
                implementer: "0x41".to_owned(),
                part: "0xd0c".to_owned(),
                revision: "1".to_owned(),
                variant: "0x0".to_owned(),
            })
        );
    }

    #[test]
    fn malformed_or_disagreeing_identities_are_omitted() {
        assert_eq!(
            identity_token(ProcessorArchitecture::X86_64, "vendor_id\t: GenuineIntel\n"),
            None
        );
        let heterogeneous = "vendor_id: a\ncpu family: 6\nmodel: 1\nstepping: 1\nmicrocode: 0x1\n\n\
                             vendor_id: a\ncpu family: 6\nmodel: 2\nstepping: 1\nmicrocode: 0x1\n";
        assert_eq!(
            identity_token(ProcessorArchitecture::X86_64, heterogeneous),
            None
        );
        let bad_number = "vendor_id: a\ncpu family: six\nmodel: 1\nstepping: 1\nmicrocode: 0x1\n";
        assert_eq!(
            identity_token(ProcessorArchitecture::X86_64, bad_number),
            None
        );
        let bad_charset = "vendor_id: a b\ncpu family: 6\nmodel: 1\nstepping: 1\nmicrocode: 0x1\n";
        assert_eq!(
            identity_token(ProcessorArchitecture::X86_64, bad_charset),
            None
        );
        assert_eq!(decode_identity_token("x86.too.few"), None);
        assert_eq!(decode_identity_token("arm.0x41.0x0.0xd0c.1.extra"), None);
        assert_eq!(decode_identity_token("x86.Upper.6.1.1.0x1"), None);
    }

    #[test]
    fn capture_is_bounded_far_below_the_observation_limits() {
        assert!(X86_FLAG_GROUPS.len() + 3 < 64);
        assert!(ARM64_HWCAP_GROUPS.len() + 1 < 64);
    }
}
