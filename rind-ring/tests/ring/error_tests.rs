#![allow(missing_docs)]

#[test]
fn error_impl_std_error_error_test() {
    #[allow(deprecated)]
    use crate::test;
    use ring::error;

    test::compile_time_assert_std_error_error::<error::Unspecified>();
    test::compile_time_assert_std_error_error::<error::KeyRejected>();
}
