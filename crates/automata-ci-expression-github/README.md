# automata-ci-expression-github

This crate evaluates the durable `github-actions` expression program emitted by
`automata-ci-workflow-github`. It is deliberately separate from parsing, job
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

The evaluator reconstructs the validated postfix tree so logical operators,
`case`, `format`, and collection functions retain upstream lazy behavior. It
also preserves identity equality for arrays/objects, insertion order for JSON
objects, case-insensitive property lookup, loose primitive comparisons, object
filters, and independent result/depth/item bounds. Debug output never renders
context values.
