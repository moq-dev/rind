//! rind's CPU check, for refusing an unsupported CPU at startup instead of panicking.
//!
//! aws-lc-rs lacks this module: AWS-LC runs on any CPU, where rind requires
//! the features [PLATFORMS.md](https://github.com/moq-dev/rind/blob/main/PLATFORMS.md) lists.

use core::fmt;

/// Checks that this CPU has every feature rind requires, naming the first one missing.
pub fn check() -> Result<(), MissingFeature> {
    rind::cpu::check().map_err(MissingFeature)
}

/// A CPU feature rind requires that this CPU lacks.
#[derive(Debug)]
pub struct MissingFeature(rind::cpu::MissingFeature);

impl fmt::Display for MissingFeature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for MissingFeature {}
