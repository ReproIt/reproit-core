//! Thin re-export of the canonical acceptance fixture.
//!
//! The fixture itself lives in `reproit_backend::fixture` behind the
//! `acceptance-fixture` feature, which the self-referential dev-dependency in
//! `Cargo.toml` enables for every test binary. Not every test binary uses
//! every re-exported item, so the allow silences the per-binary warnings.

#[allow(unused_imports)]
pub use reproit_backend::fixture::{candidate, input, seal_fixture};
