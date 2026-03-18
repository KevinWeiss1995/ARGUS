#![deny(unsafe_code)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod actions;
pub mod config;
pub mod detection;
pub mod pipeline;
pub mod security;
pub mod sources;
pub mod telemetry;
pub mod tui;
