use std::env;
use std::path::PathBuf;

fn main() {
    let cpp_dir = cmake::Config::new("cpp/").build();

    // Tell cargo to look for shared libraries in the specified directory
    println!("cargo:rustc-link-lib=static=rspcode_native");
    println!("cargo:rustc-link-search=native={}", cpp_dir.display());
    // use c++ under macos, use stdc++ under linux
    if cfg!(target_os = "macos") {
        println!("cargo:rustc-link-lib=c++");
    } else {
        println!("cargo:rustc-link-lib=stdc++");
    }

    let bindings = bindgen::Builder::default()
        .header("cpp/simple_context.hpp")
        .allowlist_recursively(true)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    // Get the output directory for the generated bindings.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    // Write the generated bindings to a file in the output directory.
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    // build sleigh
    let sleigh_bin = out_path.join("bin/sleigh");
    if !sleigh_bin.exists() {
        println!("cargo:error=Could not find sleigh binary");
    }

    let specfiles_dir = out_path.join("processors");
    if !specfiles_dir.is_dir() {
        println!("cargo:error=Could not find specfiles directory");
    }
    // execute sleigh -a specfiles_dir
    let output = std::process::Command::new(sleigh_bin)
        .arg("-a")
        .arg(specfiles_dir)
        .output()
        .expect("Failed to execute sleigh");
    println!(
        "cargo:info={}",
        String::from_utf8_lossy(&output.stdout)
    );
}
