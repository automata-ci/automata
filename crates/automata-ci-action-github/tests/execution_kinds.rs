mod support;

use automata_ci_action_github::{CompositeStep, DockerImageKind};
use support::decode;

#[test]
fn docker_metadata_preserves_deferred_expressions_and_default_conditions() {
    let metadata = decode(
        r"
name: Container
description: Container action
inputs:
  greeting:
    default: hello
runs:
  using: docker
  image: ./Dockerfile
  entrypoint: /entrypoint.sh
  args:
    - ${{ inputs.greeting }}
  env:
    GREETING: ${{ inputs.greeting }}
  pre-entrypoint: /prepare.sh
  post-entrypoint: /cleanup.sh
  post-if: failure()
",
    )
    .unwrap();
    let docker = metadata.docker().unwrap();
    assert_eq!(docker.image().kind(), DockerImageKind::Local);
    assert_eq!(docker.image().local_path().unwrap().as_str(), "Dockerfile");
    assert_eq!(docker.entrypoint().unwrap().text(), "/entrypoint.sh");
    assert_eq!(docker.arguments()[0].text(), "${{ inputs.greeting }}");
    assert_eq!(docker.environment()[0].key(), "GREETING");
    assert_eq!(docker.pre_condition().text(), "always()");
    assert_eq!(docker.post_condition().text(), "failure()");
}

#[test]
fn registry_container_images_are_distinct_from_bundle_paths() {
    let metadata =
        decode("name: C\ndescription: C\nruns:\n  using: DoCkEr\n  image: DOCKER://ubuntu:24.04\n")
            .unwrap();
    let image = metadata.docker().unwrap().image();
    assert_eq!(image.kind(), DockerImageKind::Registry);
    assert_eq!(image.as_str(), "DOCKER://ubuntu:24.04");
    assert!(image.local_path().is_none());
}

#[test]
fn composite_steps_and_output_expressions_remain_source_values() {
    let metadata = decode(
        r#"
name: Composite
description: Composite action
inputs:
  target:
    default: world
outputs:
  greeting:
    description: greeting
    value: ${{ steps.greet.outputs.value }}
runs:
  using: composite
  steps:
    - id: greet
      if: ${{ inputs.target != '' }}
      run: echo "value=hello" >> "$GITHUB_OUTPUT"
      shell: bash
      working-directory: ${{ github.workspace }}
      env:
        TARGET: ${{ inputs.target }}
      continue-on-error: false
    - name: Nested action
      uses: ./nested
      with:
        value: ${{ inputs.target }}
      env:
        MODE: test
"#,
    )
    .unwrap();
    assert_eq!(
        metadata.outputs()[0].value().unwrap().text(),
        "${{ steps.greet.outputs.value }}"
    );
    let steps = metadata.composite().unwrap().steps();
    assert_eq!(steps.len(), 2);
    let CompositeStep::Run(run) = &steps[0] else {
        panic!("first step must be run");
    };
    assert_eq!(run.shell().text(), "bash");
    assert_eq!(run.environment()[0].value().text(), "${{ inputs.target }}");
    let CompositeStep::Uses(uses) = &steps[1] else {
        panic!("second step must use an action");
    };
    assert_eq!(uses.uses().text(), "./nested");
    assert_eq!(uses.with()[0].value().text(), "${{ inputs.target }}");
}
