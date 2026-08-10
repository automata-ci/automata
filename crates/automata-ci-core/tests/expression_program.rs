use automata_ci_core::{
    EXPRESSION_PROGRAM_SCHEMA_VERSION, ExpressionDialect, ExpressionInstruction, ExpressionLiteral,
    ExpressionLogical, ExpressionProgram, ExpressionProgramError, MAX_EXPRESSION_DEPTH,
};

fn github_dialect() -> ExpressionDialect {
    ExpressionDialect::new("github-actions", 1).expect("valid dialect")
}

fn success_program() -> ExpressionProgram {
    ExpressionProgram::new(
        github_dialect(),
        "success()",
        vec![ExpressionInstruction::Call {
            name: "success".to_owned(),
            argument_count: 0,
        }],
    )
    .expect("valid program")
}

#[test]
fn current_program_round_trips_with_explicit_versions() {
    let program = success_program();
    assert_eq!(program.schema_version(), EXPRESSION_PROGRAM_SCHEMA_VERSION);
    assert_eq!(program.dialect().name(), "github-actions");
    assert_eq!(program.dialect().version(), 1);

    let encoded = serde_json::to_string(&program).expect("serialize");
    let decoded: ExpressionProgram = serde_json::from_str(&encoded).expect("deserialize");
    assert_eq!(decoded, program);
}

#[test]
fn deserialization_revalidates_schema_and_rejects_unknown_fields() {
    let mut encoded = serde_json::to_value(success_program()).expect("serialize");
    encoded["schema_version"] = serde_json::json!(2);
    assert!(serde_json::from_value::<ExpressionProgram>(encoded).is_err());

    let mut encoded = serde_json::to_value(success_program()).expect("serialize");
    encoded["future_required_field"] = serde_json::json!(true);
    assert!(serde_json::from_value::<ExpressionProgram>(encoded).is_err());
}

#[test]
fn malformed_stack_programs_are_rejected() {
    assert_eq!(
        ExpressionProgram::new(github_dialect(), "!", vec![ExpressionInstruction::Not],),
        Err(ExpressionProgramError::StackUnderflow)
    );
    assert_eq!(
        ExpressionProgram::new(
            github_dialect(),
            "true false",
            vec![
                ExpressionInstruction::Literal {
                    value: ExpressionLiteral::Boolean { value: true },
                },
                ExpressionInstruction::Literal {
                    value: ExpressionLiteral::Boolean { value: false },
                },
            ],
        ),
        Err(ExpressionProgramError::InvalidFinalStack { values: 2 })
    );
}

#[test]
fn wildcard_and_flattened_logical_invariants_are_typed() {
    let wildcard_target = vec![
        ExpressionInstruction::Wildcard,
        ExpressionInstruction::Literal {
            value: ExpressionLiteral::String {
                value: "name".to_owned(),
            },
        },
        ExpressionInstruction::Index,
    ];
    assert_eq!(
        ExpressionProgram::new(github_dialect(), "*.name", wildcard_target),
        Err(ExpressionProgramError::WildcardOutsideIndex)
    );

    let nested_and = vec![
        ExpressionInstruction::Literal {
            value: ExpressionLiteral::Boolean { value: true },
        },
        ExpressionInstruction::Literal {
            value: ExpressionLiteral::Boolean { value: true },
        },
        ExpressionInstruction::Logical {
            operator: ExpressionLogical::And,
            operand_count: 2,
        },
        ExpressionInstruction::Literal {
            value: ExpressionLiteral::Boolean { value: true },
        },
        ExpressionInstruction::Logical {
            operator: ExpressionLogical::And,
            operand_count: 2,
        },
    ];
    assert_eq!(
        ExpressionProgram::new(github_dialect(), "true && true && true", nested_and),
        Err(ExpressionProgramError::NonCanonicalLogicalNesting)
    );
}

#[test]
fn depth_and_nan_encoding_have_durable_limits() {
    let mut instructions = vec![ExpressionInstruction::Literal {
        value: ExpressionLiteral::Boolean { value: true },
    }];
    instructions.extend((0..MAX_EXPRESSION_DEPTH).map(|_| ExpressionInstruction::Not));
    assert_eq!(
        ExpressionProgram::new(github_dialect(), "deep", instructions),
        Err(ExpressionProgramError::TooDeep {
            maximum: MAX_EXPRESSION_DEPTH
        })
    );

    let noncanonical_nan = vec![ExpressionInstruction::Literal {
        value: ExpressionLiteral::Number {
            ieee754_bits: 0x7ff8_0000_0000_0001,
        },
    }];
    assert_eq!(
        ExpressionProgram::new(github_dialect(), "NaN", noncanonical_nan),
        Err(ExpressionProgramError::NonCanonicalNan)
    );
}

#[test]
fn dialect_and_instruction_identifiers_are_canonical() {
    assert_eq!(
        ExpressionDialect::new("GitHub-Actions", 1),
        Err(ExpressionProgramError::InvalidDialect)
    );
    assert_eq!(
        ExpressionDialect::new("github..actions", 1),
        Err(ExpressionProgramError::InvalidDialect)
    );
    assert_eq!(
        ExpressionDialect::new("github-actions.", 1),
        Err(ExpressionProgramError::InvalidDialect)
    );
    assert_eq!(
        ExpressionDialect::new("github\0actions", 1),
        Err(ExpressionProgramError::InvalidDialect)
    );
    assert_eq!(
        ExpressionProgram::new(
            github_dialect(),
            "Success()",
            vec![ExpressionInstruction::Call {
                name: "Success".to_owned(),
                argument_count: 0,
            }],
        ),
        Err(ExpressionProgramError::InvalidIdentifier)
    );
}
