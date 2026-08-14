use automata_ci_core::{
    ExpressionComparison, ExpressionInstruction, ExpressionLiteral, ExpressionLogical,
};
use automata_ci_workflow_github::{
    GITHUB_EXPRESSION_MAX_UTF16_UNITS, GithubConditionCompiler, GithubConditionPhase,
    GithubExpressionErrorKind, GithubExpressionLimits,
};

fn compile(source: &str, phase: GithubConditionPhase) -> automata_ci_core::ExpressionProgram {
    GithubConditionCompiler::default()
        .compile_condition(Some(source), phase)
        .expect("valid condition")
}

#[test]
fn missing_and_whitespace_conditions_become_success() {
    let compiler = GithubConditionCompiler::default();
    for source in [None, Some(" \n\t ")] {
        let program = compiler
            .compile_condition(source, GithubConditionPhase::Job)
            .expect("default condition");
        assert_eq!(program.source(), "success()");
        assert_eq!(
            program.instructions(),
            [ExpressionInstruction::Call {
                name: "success".to_owned(),
                argument_count: 0,
            }]
        );
    }
}

#[test]
fn implicit_success_is_injected_and_logical_operators_are_flattened() {
    let program = compile(
        "github.ref == 'refs/heads/main' && vars.READY == 'yes'",
        GithubConditionPhase::Job,
    );
    assert_eq!(
        program.source(),
        "github.ref == 'refs/heads/main' && vars.READY == 'yes'"
    );
    assert!(matches!(
        program.instructions().first(),
        Some(ExpressionInstruction::Call { name, argument_count: 0 }) if name == "success"
    ));
    assert!(matches!(
        program.instructions().last(),
        Some(ExpressionInstruction::Logical {
            operator: ExpressionLogical::And,
            operand_count: 3,
        })
    ));
}

#[test]
fn every_status_function_suppresses_implicit_success_at_any_depth() {
    for function in ["always", "success", "failure", "cancelled"] {
        let source = format!("contains('x', 'x') && {function}()");
        let program = compile(&source, GithubConditionPhase::Step);
        let calls = program
            .instructions()
            .iter()
            .filter_map(|instruction| match instruction {
                ExpressionInstruction::Call { name, .. } => Some(name.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            calls.iter().filter(|name| **name == "success").count(),
            usize::from(function == "success")
        );
        assert!(calls.contains(&function));
    }
}

#[test]
fn explicit_step_ids_and_property_case_are_preserved_as_index_literals() {
    let program = compile(
        "${{ steps.Build-Artifact.outputs.Digest == 'expected' }}",
        GithubConditionPhase::Step,
    );
    let strings = program
        .instructions()
        .iter()
        .filter_map(|instruction| match instruction {
            ExpressionInstruction::Literal {
                value: ExpressionLiteral::String { value },
            } => Some(value.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(
        strings
            .windows(3)
            .any(|values| values == ["Build-Artifact", "outputs", "Digest"])
    );
}

#[test]
fn job_and_step_contexts_are_phase_specific_and_late_bound() {
    compile("needs.build.result == 'success'", GithubConditionPhase::Job);
    compile("matrix.os == 'linux'", GithubConditionPhase::Step);

    let error = GithubConditionCompiler::default()
        .compile_condition(Some("matrix.os == 'linux'"), GithubConditionPhase::Job)
        .expect_err("matrix is unavailable before job expansion");
    assert_eq!(error.kind(), GithubExpressionErrorKind::Context);
    assert_eq!(error.code(), "github.expression.unrecognized_context");

    let error = GithubConditionCompiler::default()
        .compile_condition(Some("secrets.TOKEN != ''"), GithubConditionPhase::Step)
        .expect_err("secrets are not read during condition planning");
    assert_eq!(error.code(), "github.expression.unrecognized_context");
}

#[test]
fn function_availability_and_arity_match_the_condition_phase() {
    compile("hashFiles('**/*.rs') != ''", GithubConditionPhase::Step);
    let error = GithubConditionCompiler::default()
        .compile_condition(Some("hashFiles('**/*.rs')"), GithubConditionPhase::Job)
        .expect_err("hashFiles is step-only");
    assert_eq!(error.code(), "github.expression.unrecognized_function");

    let error = GithubConditionCompiler::default()
        .compile_condition(Some("always(true)"), GithubConditionPhase::Step)
        .expect_err("always accepts no parameters");
    assert_eq!(error.code(), "github.expression.too_many_arguments");

    compile("failure('build')", GithubConditionPhase::Job);
}

#[test]
fn case_literals_indices_and_comparison_syntax_compile_canonically() {
    let program = compile(
        "case(github.event_name == 'push', 0x10, github['attempt'] >= 0o7, .5e+2, null)",
        GithubConditionPhase::Job,
    );
    assert!(program.instructions().iter().any(|instruction| matches!(
        instruction,
        ExpressionInstruction::Call { name, argument_count: 5 } if name == "case"
    )));
    assert!(program.instructions().iter().any(|instruction| matches!(
        instruction,
        ExpressionInstruction::Compare {
            operator: ExpressionComparison::GreaterThanOrEqual
        }
    )));

    let error = GithubConditionCompiler::default()
        .compile_condition(
            Some("case(true, 'yes', false, 'no')"),
            GithubConditionPhase::Step,
        )
        .expect_err("case requires an odd argument count");
    assert_eq!(error.code(), "github.expression.even_case_arguments");
}

#[test]
fn hexadecimal_and_octal_literals_use_github_signed_i32_bits() {
    let program = compile(
        "0xFFFFFFFF == -1 && 0o37777777777 == -1",
        GithubConditionPhase::Step,
    );
    let negative_one = (-1.0_f64).to_bits();
    assert_eq!(
        program
            .instructions()
            .iter()
            .filter(|instruction| matches!(
                instruction,
                ExpressionInstruction::Literal {
                    value: ExpressionLiteral::Number { ieee754_bits }
                } if *ieee754_bits == negative_one
            ))
            .count(),
        4
    );
}

#[test]
fn property_keywords_strings_wildcards_and_escaped_quotes_are_accepted() {
    let program = compile(
        "github.true == 'it''s' && github.event.commits.*.message != ''",
        GithubConditionPhase::Job,
    );
    assert!(
        program
            .instructions()
            .iter()
            .any(|instruction| matches!(instruction, ExpressionInstruction::Wildcard))
    );
    assert!(program.instructions().iter().any(|instruction| matches!(
        instruction,
        ExpressionInstruction::Literal { value: ExpressionLiteral::String { value } } if value == "it's"
    )));
}

#[test]
fn expression_delimiters_inside_single_quoted_literals_are_data() {
    for source in ["${{ contains('}}', '${{') }}", "contains('}}', '${{')"] {
        let program = compile(source, GithubConditionPhase::Step);
        let strings = program
            .instructions()
            .iter()
            .filter_map(|instruction| match instruction {
                ExpressionInstruction::Literal {
                    value: ExpressionLiteral::String { value },
                } => Some(value.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(strings.contains(&"}}"));
        assert!(strings.contains(&"${{"));
    }
}

#[test]
fn invalid_syntax_reports_exact_offsets_in_preserved_source() {
    let compiler = GithubConditionCompiler::default();
    let source = "  ${{ github.ref = 'main' }}  ";
    let error = compiler
        .compile_condition(Some(source), GithubConditionPhase::Job)
        .expect_err("assignment is invalid");
    assert_eq!(error.kind(), GithubExpressionErrorKind::Syntax);
    assert_eq!(error.code(), "github.expression.unexpected_symbol");
    assert_eq!(
        &source[error.byte_offset()..error.byte_offset() + error.byte_length()],
        "="
    );

    for malformed in [
        "github.ref == 'unterminated",
        "github.ref ==",
        "(github.ref == 'x'",
        "github..ref",
        "${{ github.ref }} trailing",
        "${{ }}",
        "'literal'.property",
        "true[0]",
        "github.foo$bar",
    ] {
        assert!(
            compiler
                .compile_condition(Some(malformed), GithubConditionPhase::Job)
                .is_err(),
            "accepted malformed condition: {malformed}"
        );
    }
}

#[test]
fn input_node_depth_and_text_budgets_fail_independently() {
    let input_limits = GithubExpressionLimits::new(8, 32, 16, 64).expect("limits");
    let error = GithubConditionCompiler::new(input_limits)
        .compile_condition(Some("github.ref"), GithubConditionPhase::Job)
        .expect_err("input budget");
    assert_eq!(error.code(), "github.expression.input_limit");
    let error = GithubConditionCompiler::new(input_limits)
        .compile_condition(Some("         "), GithubConditionPhase::Job)
        .expect_err("whitespace still consumes input budget");
    assert_eq!(error.code(), "github.expression.input_limit");

    let node_limits = GithubExpressionLimits::new(128, 3, 16, 64).expect("limits");
    let error = GithubConditionCompiler::new(node_limits)
        .compile_condition(Some("github.ref"), GithubConditionPhase::Job)
        .expect_err("node budget includes implicit guard");
    assert_eq!(error.code(), "github.expression.node_limit");

    let depth_limits = GithubExpressionLimits::new(128, 64, 2, 64).expect("limits");
    let error = GithubConditionCompiler::new(depth_limits)
        .compile_condition(Some("!!!true"), GithubConditionPhase::Step)
        .expect_err("depth budget");
    assert_eq!(error.code(), "github.expression.depth_limit");

    let deep_property_chain = format!("github{}", ".ref".repeat(64));
    let error = GithubConditionCompiler::default()
        .compile_condition(Some(&deep_property_chain), GithubConditionPhase::Step)
        .expect_err("postfix depth is bounded while parsing");
    assert_eq!(error.code(), "github.expression.depth_limit");

    let deep_comparison_chain = std::iter::repeat_n("true", 64)
        .collect::<Vec<_>>()
        .join(" == ");
    let error = GithubConditionCompiler::default()
        .compile_condition(Some(&deep_comparison_chain), GithubConditionPhase::Step)
        .expect_err("left-associative depth is bounded while parsing");
    assert_eq!(error.code(), "github.expression.depth_limit");

    let text_limits = GithubExpressionLimits::new(128, 64, 16, 3).expect("limits");
    let error = GithubConditionCompiler::new(text_limits)
        .compile_condition(Some("'four'"), GithubConditionPhase::Step)
        .expect_err("instruction text budget");
    assert_eq!(error.code(), "github.expression.text_limit");
}

#[test]
fn scalar_value_expression_does_not_receive_a_condition_status_guard() {
    let program = GithubConditionCompiler::default()
        .compile_value_expression("${{ github.token }}", GithubConditionPhase::Step)
        .expect("valid action input default");

    assert_eq!(program.source(), "${{ github.token }}");
    assert_eq!(program.instructions().len(), 3);
    assert!(matches!(
        &program.instructions()[0],
        automata_ci_core::ExpressionInstruction::NamedValue { name } if name == "github"
    ));
    assert!(matches!(
        &program.instructions()[1],
        automata_ci_core::ExpressionInstruction::Literal {
            value: automata_ci_core::ExpressionLiteral::String { value }
        } if value == "token"
    ));
    assert!(matches!(
        &program.instructions()[2],
        automata_ci_core::ExpressionInstruction::Index
    ));
}

#[test]
fn upstream_utf16_limit_is_enforced_separately_from_utf8_bytes() {
    let mut source = "a".repeat(GITHUB_EXPRESSION_MAX_UTF16_UNITS);
    source.push('a');
    let error = GithubConditionCompiler::default()
        .compile_condition(Some(&source), GithubConditionPhase::Step)
        .expect_err("GitHub UTF-16 ceiling");
    assert_eq!(error.code(), "github.expression.github_length_limit");

    let inner = format!("'{}'", "a".repeat(GITHUB_EXPRESSION_MAX_UTF16_UNITS - 2));
    let wrapped = format!("${{{{ {inner} }}}}");
    GithubConditionCompiler::default()
        .compile_condition(Some(&wrapped), GithubConditionPhase::Step)
        .expect("delimiters and outer whitespace do not count toward GitHub's parser limit");
}

#[test]
fn malformed_generated_inputs_are_bounded_and_never_panic() {
    let compiler = GithubConditionCompiler::default();
    let alphabet = b"ab_.!<>=&|()[],'0123$}{*-+ ";
    let mut state = 0x5eed_u64;
    for length in 0..256 {
        let mut source = String::with_capacity(length);
        for _ in 0..length {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            let selector = u8::try_from(state & 0xff).expect("masked selector");
            source.push(char::from(alphabet[usize::from(selector) % alphabet.len()]));
        }
        let _ = compiler.compile_condition(Some(&source), GithubConditionPhase::Step);
    }
}
