//! Feature extractors — the Rust half of the feature parity seams. Each submodule
//! mirrors a `ml/synthaea_ml/features/` definition exactly, pinned by a shared golden
//! fixture (drift is a CI failure on both sides).

pub mod cmdline;
pub mod correlation;
pub mod lineage;
