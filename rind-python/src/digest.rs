// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rind::digest;

use crate::{Bytes, algorithm, bytes, constants, submodule};

algorithm!(
    /// A hash function.
    Algorithm(digest::Algorithm) as "pyrind.digest"."Algorithm" {
    /// The digest's length in bytes.
    #[getter]
    fn output_len(&self) -> usize {
        self.inner.output_len()
    }
    }
);

/// Returns the digest of `data`.
#[pyfunction(name = "digest")]
fn digest_of<'py>(
    py: Python<'py>,
    algorithm: &Bound<'_, Algorithm>,
    data: Bytes<'_>,
) -> Bound<'py, PyBytes> {
    bytes(py, digest::digest(algorithm.get().inner, &data))
}

/// A hash of a message given in pieces.
#[pyclass(module = "pyrind.digest")]
struct Context(Box<digest::Context>);

#[pymethods]
impl Context {
    /// Starts hashing with `algorithm`.
    #[new]
    fn new(algorithm: &Bound<'_, Algorithm>) -> Self {
        Self(Box::new(digest::Context::new(algorithm.get().inner)))
    }

    /// Adds `data` to the message.
    fn update(&mut self, data: Bytes<'_>) {
        self.0.update(&data);
    }

    /// Returns the digest of the message, and starts a new one with the same
    /// algorithm.
    fn finish<'py>(&mut self, py: Python<'py>) -> Bound<'py, PyBytes> {
        bytes(py, self.0.finish())
    }
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Algorithm>()?;
    m.add_class::<Context>()?;
    m.add_function(wrap_pyfunction!(digest_of, m)?)?;
    constants!(m, Algorithm, "pyrind.digest", {
        SHA256 => &digest::SHA256,
        SHA384 => &digest::SHA384,
        SHA512 => &digest::SHA512,
        SHA512_256 => &digest::SHA512_256,
        SHA3_256 => &digest::SHA3_256,
        SHA3_384 => &digest::SHA3_384,
        SHA3_512 => &digest::SHA3_512,
    });
    submodule(m, "pyrind.digest.legacy", |legacy| {
        constants!(legacy, Algorithm, "pyrind.digest.legacy", {
            MD5 => &digest::legacy::MD5,
            SHA1 => &digest::legacy::SHA1,
        });
        Ok(())
    })
}
