extern crate compiletest_rs as compiletest;

use std::process::Command;
use std::{env, fs};

fn run_mode(mode: &'static str) {
    let config = compiletest::Config {
        mode: mode.parse().expect("invalid mode"),
        target_rustcflags: Some(String::from(
            "\
             --edition=2018 \
             --extern oauth1_request \
             -L test-deps/target/debug/deps \
             ",
        )),
        src_base: format!("tests/{}", mode).into(),
        ..Default::default()
    };

    let deps = "test-deps/target/debug/deps";
    if fs::metadata(deps).is_ok() {
        for entry in fs::read_dir(deps).unwrap() {
            let path = entry.unwrap().path();
            if path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("liboauth1_request-")
            {
                fs::remove_file(path).unwrap();
            }
        }
    }

    let status = Command::new("cargo")
        .arg("build")
        .arg("--target-dir")
        .arg("test-deps/target")
        .arg("--manifest-path")
        .arg("test-deps/Cargo.toml")
        .status()
        .unwrap();
    if !status.success() {
        panic!("failed to build test dependencies");
    }

    env::set_var("CARGO_MANIFEST_DIR", "test-deps");

    compiletest::run_tests(&config);
}

#[test]
fn compile_test() {
    run_mode("compile-fail");
}
