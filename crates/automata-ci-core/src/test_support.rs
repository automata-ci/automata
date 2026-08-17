macro_rules! limit_contract_tests {
    (
        $(
            $name:ident: (
                $check:path,
                $maximum:path
                $(, $argument:expr)*
                $(,)?
            ) => $above:expr;
        )+
    ) => {
        mod limit_contract_tests {
            $(
                #[test]
                fn $name() {
                    assert_eq!($check($maximum - 1 $(, $argument)*), None);
                    assert_eq!($check($maximum $(, $argument)*), None);
                    assert_eq!($check($maximum + 1 $(, $argument)*), Some($above));
                }
            )+
        }
    };
}

pub(crate) use limit_contract_tests;
