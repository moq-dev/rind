# aws-lc and BoringSSL vector files

Copies of the vector files in [aws-lc] and [BoringSSL] that cover an
algorithm rind offers. `admin/sync-vectors` fetches them, unmodified, from the
revisions it pins, and lists every file. Both repositories are hundreds of
megabytes, so rind keeps these copies rather than submodules.

Each directory holds its upstream's `LICENSE`. To update, bump a revision in
`admin/sync-vectors` and rerun it.

The tests read them through `rind/src/test/file_test.rs`, which parses the
FileTest format both projects share.

[aws-lc]: https://github.com/aws/aws-lc
[BoringSSL]: https://boringssl.googlesource.com/boringssl
