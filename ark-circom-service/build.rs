use std::env;

fn main() {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();

    if target_os == "android" {
        println!("cargo:rustc-link-search=native=/home/cguth/Vidar/backend/ark-circom-service/lib/aarch64-linux-android");
        println!("cargo:rustc-link-search=native=/home/cguth/Android/Sdk/ndk/25.1.8937393/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/aarch64-linux-android/33");

        println!("cargo:rustc-link-lib=dylib=c++");
        println!("cargo:rustc-link-lib=static=gmp");
        println!("cargo:rustc-link-lib=static=fr");

        println!("cargo:rustc-link-lib=static=poseidon_bench");
    } else {
        println!("cargo:rustc-link-search=native=/home/cguth/Vidar/backend/ark-circom-service/lib/x86_64-unknown-linux-gnu");
        println!("cargo:rustc-link-search=native=/usr/lib/gcc/x86_64-linux-gnu/10/"); //path to libstdc++.a
    
        println!("cargo:rustc-link-lib=static=stdc++");
        println!("cargo:rustc-link-lib=static=gmp");
        println!("cargo:rustc-link-lib=static=fr");
    
        println!("cargo:rustc-link-lib=static=poseidon_bench");
    }
}

