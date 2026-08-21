//! Replay-host processor observation.
//!
//! One narrow effectful adapter over the pure capture rule in
//! `reproit_core::model::processor_capture`. The worker and every other
//! host-side consumer observe the host through this single function, so the
//! replay host and the capturing SDK derive capabilities from the same
//! pinned contract in `specs/v1/processor-capture.json`.

use reproit_core::Error;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use reproit_core::model;

/// Observe the current Linux host and return its sorted `processor.*`
/// capability list. A non-Linux host observes nothing. A read failure
/// observes nothing, because capture may only add real information.
pub fn observe_host_processor_capabilities() -> Vec<String> {
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        let architecture = if cfg!(target_arch = "aarch64") {
            model::ProcessorArchitecture::Arm64
        } else {
            model::ProcessorArchitecture::X86_64
        };
        let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
        let hwcap = std::fs::read("/proc/self/auxv")
            .ok()
            .as_deref()
            .and_then(model::parse_auxv_hwcap);
        model::capture_processor_capabilities(architecture, &cpuinfo, hwcap).capabilities
    }
    #[cfg(not(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )))]
    {
        Vec::new()
    }
}

/// Merge host-observed processor capabilities into a configured capability
/// list. A configured `processor.*` entry that the host does not observe is
/// a configuration conflict: attested evidence must never declare a
/// processor view the host cannot supply, so this fails closed.
pub fn merge_host_processor_capabilities(configured: &[String]) -> Result<Vec<String>, Error> {
    let observed = observe_host_processor_capabilities();
    for entry in configured {
        if entry.starts_with("processor.") && !observed.iter().any(|value| value == entry) {
            return Err(Error::schema_invalid());
        }
    }
    let mut merged = configured.to_vec();
    merged.extend(observed);
    merged.sort();
    merged.dedup();
    if merged.len() > 64 {
        return Err(Error::schema_invalid());
    }
    Ok(merged)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_observation_is_sorted_unique_and_prefixed() {
        let observed = observe_host_processor_capabilities();
        let mut sorted = observed.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(observed, sorted);
        assert!(observed.iter().all(|value| value.starts_with("processor.")));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_linux_host_observes_at_least_one_processor_capability() {
        assert!(!observe_host_processor_capabilities().is_empty());
    }

    #[test]
    fn merging_keeps_configured_entries_and_stays_bounded() {
        let configured = vec!["core.v1".to_owned(), "sdk.rust".to_owned()];
        let merged = merge_host_processor_capabilities(&configured).unwrap();
        assert!(merged.contains(&"core.v1".to_owned()));
        assert!(merged.contains(&"sdk.rust".to_owned()));
        assert!(merged.len() <= 64);
        let mut sorted = merged.clone();
        sorted.sort();
        assert_eq!(merged, sorted);
    }

    #[test]
    fn a_configured_processor_entry_the_host_lacks_fails_closed() {
        let configured = vec!["processor.feature.fixture-absent".to_owned()];
        assert!(merge_host_processor_capabilities(&configured).is_err());
    }
}
