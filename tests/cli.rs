use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn help_does_not_panic() {
    let mut cmd = Command::cargo_bin("okta-awscli-rs").unwrap();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage: okta-awscli "))
        .stdout(predicate::str::contains("--profile"));
}
