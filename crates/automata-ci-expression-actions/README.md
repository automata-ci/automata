# automata-ci-expression-actions

This crate evaluates the durable `github-actions` expression program emitted by
`automata-ci-workflow-actions`. It is deliberately separate from parsing, job
execution, and filesystem access. Side-effecting functions such as `hashFiles`
cross the object-safe `GithubExpressionFunctionProvider` boundary.

The compatibility baseline is `actions/runner@v2.336.0`, commit
`98aabcd429c4e8402406c56ce2d26387fed3b9ce`. The implementation was reviewed
against these upstream MIT-licensed sources:

- `src/Sdk/DTExpressions2/Expressions2/EvaluationResult.cs`
- `src/Sdk/DTExpressions2/Expressions2/Sdk/Operators/Index.cs`
- `src/Sdk/DTExpressions2/Expressions2/Sdk/Operators/{And,Or,Not,Equal,NotEqual,GreaterThan,GreaterThanOrEqual,LessThan,LessThanOrEqual}.cs`
- `src/Sdk/DTExpressions2/Expressions2/Sdk/Functions/{Case,Contains,StartsWith,EndsWith,Format,Join,FromJson,ToJson}.cs`
- `src/Runner.Worker/Expressions/{Always,Success,Failure,Cancelled,HashFiles}Function.cs`
- `src/Sdk/DTPipelines/workflow-v1.0.json`

The evaluator reconstructs the validated postfix tree so logical operators,
`case`, `format`, and collection functions retain upstream lazy behavior. It
also preserves identity equality for arrays/objects, insertion order for JSON
objects, case-insensitive property lookup, loose primitive comparisons, object
filters, and independent result/depth/item bounds. Debug output never renders
context values.

## Closed compatibility contract

The compiler admits a closed built-in set and the evaluator validates the same
signature before evaluating argument subtrees. `always()` and `cancelled()` are
zero-argument functions in every condition phase. Step `success()` and
`failure()` are also zero-argument. The pinned runner schema deliberately
registers job-condition `success(0,MAX)` and `failure(0,MAX)`; their upstream
implementations only inspect job status, so Automata accepts nonzero arguments
in that phase and lazily ignores every argument subtree. Known-invalid arities
never fall through to an extension provider.

`case` is not an Automata extension. It is a well-known function in the pinned
runner's `DTExpressions2` engine (`Case.cs`), with 3–255 odd arguments and lazy
predicate/result evaluation. Although it is absent from the public Actions
expression reference, Automata classifies it as a pinned-runner compatibility
surface and guards that classification with compiler and evaluator fixtures.

Loose equality and relational comparison follow the pinned runner's null,
boolean, numeric-string, hexadecimal/octal signed-32-bit, exponent, infinity,
NaN, and negative-zero rules. Strings and object keys use .NET-style ordinal
ignore-case semantics, including one-to-one non-ASCII casing and UTF-16 ordinal
ordering; no locale or multi-character Unicode normalization is applied.

## Sensitive values

`GithubValue::Sensitive` carries an opaque payload whose wrapper cannot be
destructured outside this crate. `github.token`, the `secrets` context, and
secret executor inputs/environment values enter evaluation through this type.
Indexing and wildcards preserve the marker; logical and comparison operations,
`case`, `contains`, `startsWith`, `endsWith`, `format`, `join`, `fromJSON`, and
extension results propagate it from every evaluated input. Lazily skipped
inputs do not taint a result.

`toJSON` rejects a value when the value or any descendant is sensitive. Debug
and evaluation errors never contain payloads. Typed accessors such as `as_str`
return `None` for an opaque value. `coerce_to_string()` is the sole explicit
payload-exposure boundary and is used only when the job executor hands an
already-masked value to a process; callers must retain the existing secret
custody and masking controls after crossing that boundary.
