use reproit_core::contracts::{CLOUD_API_SCHEMAS, CORE_SCHEMAS, MCP_SCHEMAS, PROTOCOL_VECTORS};

#[test]
fn packaged_contracts_match_the_canonical_specs() {
    for (packaged, canonical) in [
        (CORE_SCHEMAS, include_str!("../../../specs/v1/schemas.json")),
        (
            CLOUD_API_SCHEMAS,
            include_str!("../../../specs/v1/cloud-api-schemas.json"),
        ),
        (
            MCP_SCHEMAS,
            include_str!("../../../specs/v1/mcp-schemas.json"),
        ),
        (
            PROTOCOL_VECTORS,
            include_str!("../../../specs/v1/protocol-vectors.json"),
        ),
    ] {
        assert_eq!(packaged.as_bytes(), canonical.as_bytes());
    }
}
