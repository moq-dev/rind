// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! A reader for BoringSSL's `FileTest` vector format, which aws-lc shares,
//! for the files under `thirdparty/vectors`. The unit tests and
//! `tests/aws_lc.rs` both include it.

/// One test of a vector file: its attributes, and the bracketed
/// instructions in force.
pub(crate) struct Test {
    path: String,
    line: usize,
    attributes: Vec<(String, String)>,
    instructions: Vec<(String, String)>,
}

impl Test {
    pub(crate) fn get(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .chain(&self.instructions)
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    pub(crate) fn str(&self, name: &str) -> &str {
        self.get(name)
            .unwrap_or_else(|| panic!("{self}: no {name}"))
    }

    /// A value as bytes: a quoted string's, or else hex.
    pub(crate) fn bytes(&self, name: &str) -> Vec<u8> {
        let value = self.str(name);
        match value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
            Some(text) => text.as_bytes().to_vec(),
            None => hex::decode(value).unwrap_or_else(|e| panic!("{self}: {name}: {e}")),
        }
    }
}

impl core::fmt::Display for Test {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}:{}", self.path, self.line)
    }
}

/// Reads every test of the vector file at `path` under `thirdparty/vectors`,
/// in BoringSSL's `FileTest` format.
pub(crate) fn tests(path: &str) -> Vec<Test> {
    let full = format!(
        "{}/../thirdparty/vectors/{path}",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&full).unwrap_or_else(|_| panic!("cannot open {full}"));

    let mut tests = Vec::new();
    let mut instructions = Vec::new();
    let mut attributes = Vec::new();
    let mut start = 0;
    // A block of instructions after a test replaces the one before it.
    let mut tested = false;
    for (i, line) in text.lines().chain([""]).enumerate() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if line.is_empty() {
            if !attributes.is_empty() {
                tests.push(Test {
                    path: path.to_string(),
                    line: start + 1,
                    attributes: core::mem::take(&mut attributes),
                    instructions: instructions.clone(),
                });
                tested = true;
            }
            continue;
        }
        if let Some(inner) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            if tested {
                instructions.clear();
                tested = false;
            }
            instructions.push(split(inner));
            continue;
        }
        if attributes.is_empty() {
            start = i;
        }
        attributes.push(split(line));
    }
    assert!(!tests.is_empty(), "{full} has no tests");
    tests
}

/// Splits `Name = value` or `Name: value`.
fn split(line: &str) -> (String, String) {
    let at = line.find([':', '=']).unwrap_or(line.len());
    let (name, value) = line.split_at(at);
    let value = value.get(1..).unwrap_or("");
    (name.trim().to_string(), value.trim().to_string())
}
