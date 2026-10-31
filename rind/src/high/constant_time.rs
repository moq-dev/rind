// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use crate::Error;
use crate::low::{ct, ct_equal};

/// Checks in constant time that `a` and `b` hold the same bytes.
///
/// Their lengths are public: unequal ones fail with [`Error::WrongLength`]
/// before either is read. Unequal contents fail with [`Error::NotEqual`],
/// after reading every byte of both.
///
/// Unlike aws-lc-rs's opaque `Unspecified`, the two failures differ, since
/// telling them apart reveals only the lengths.
pub fn verify_slices_are_equal(a: &[u8], b: &[u8]) -> Result<(), Error> {
    if a.len() != b.len() {
        return Err(Error::WrongLength);
    }
    match ct::into_public(ct_equal(a, b)) {
        true => Ok(()),
        false => Err(Error::NotEqual),
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    // Under `admin/ctgrind`, memcheck fails this if the comparison branches on
    // or indexes by either slice's contents.
    #[test]
    fn contents_stay_secret() {
        for len in [0, 1, 16, 32, 64, 255] {
            let a = vec![0x5a; len];
            ct::secret_slice(&a);

            let b = vec![0x5a; len];
            ct::secret_slice(&b);
            assert_eq!(verify_slices_are_equal(&a, &b), Ok(()));

            for i in 0..len {
                let mut b = vec![0x5a; len];
                b[i] = 0xa5;
                ct::secret_slice(&b);
                assert_eq!(verify_slices_are_equal(&a, &b), Err(Error::NotEqual));
            }
        }
    }

    #[test]
    fn unequal_lengths() {
        assert_eq!(verify_slices_are_equal(&[], &[0]), Err(Error::WrongLength));
        assert_eq!(
            verify_slices_are_equal(&[0; 32], &[0; 31]),
            Err(Error::WrongLength)
        );
        // A prefix of the other is still refused.
        assert_eq!(
            verify_slices_are_equal(b"tag", b"tag\0"),
            Err(Error::WrongLength)
        );
    }
}
