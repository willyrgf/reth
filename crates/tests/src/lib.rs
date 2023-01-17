#![warn(missing_docs, unreachable_pub)]
#![deny(unused_must_use, rust_2018_idioms)]
#![doc(test(
    no_crate_inject,
    attr(deny(warnings, rust_2018_idioms), allow(dead_code, unused_variables))
))]

//! Integration tests and test helpers for reth.
#[cfg(test)]
mod clique;

#[cfg(test)]
mod sync;

#[cfg(test)]
mod reth_builder;

#[cfg(test)]
mod stage_config;
