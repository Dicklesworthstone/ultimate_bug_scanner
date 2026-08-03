// GH #75: an excluded directory must not contribute type-narrowing findings.
// This file deliberately contains the guard-without-exit pattern; when the
// scan excludes "tests" the helper must never see it.
interface Fixture {
  label?: string;
}

export function describeFixture(fixture?: Fixture) {
  if (!fixture) {
    console.warn("missing fixture");
  }

  console.log("fixture label", fixture.label!.toUpperCase());
}
