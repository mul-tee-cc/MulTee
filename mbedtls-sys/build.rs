use std::{env, path::Path};

use bindgen;
use bindgen::Formatter;
use cc;

const MBEDTLS_SRC_FILES: &[&str] = {
  &[
    "aes.c",
    "aesni.c",
    "asn1parse.c",
    "asn1write.c",
    "base64.c",
    "bignum.c",
    "blowfish.c",
    "ccm.c",
    "certs.c",
    "cipher.c",
    "cipher_wrap.c",
    "cmac.c",
    "ctr_drbg.c",
    // "hmac_drbg.c",
    "entropy_poll.c",
    "entropy.c",
    "ecdh.c",
    "ecdsa.c",
    "ecp.c",
    "ecp_curves.c",
    "error.c",
    "gcm.c",
    "md.c",
    "oid.c",
    "pem.c",
    "pk.c",
    "pk_wrap.c",
    "pkcs12.c",
    "pkcs5.c",
    "pkparse.c",
    "pkwrite.c",
    "rsa.c",
    "rsa_internal.c",
    "sha256.c",
    "sha512.c",
    "x509.c",
    "x509_create.c",
    "x509_crl.c",
    "x509_crt.c",
    "x509_csr.c",
    "x509write_crt.c",
    "x509write_csr.c",
    "platform.c",
    "platform_util.c",
    "constant_time.c",
    "threading.c",
    "havege.c",
    "timing.c",
    "nist_kw.c",
  ]
};

fn rerun_if_changed<P: AsRef<Path>>(file: P) {
  println!("cargo:rerun-if-changed={}", file.as_ref().display());
}

fn main() {
  //  let mbedtls_dir = Path::new("./mbedtls");
  let mbedtls_dir = Path::new("../deps/mbedtls");
  let mbedtls_src_dir = mbedtls_dir.join("library");
  let mbedtls_src_files = MBEDTLS_SRC_FILES.iter().map(|s| mbedtls_src_dir.join(s));
  let mbedtls_include_dir = mbedtls_dir.join("include");

  let (c_def1, cpu) = if cfg!(feature = "multee_sgx") {
    ("-DMULTEE_X86_SGX", "-march=skylake")
  } else if cfg!(feature = "multee_devm") {
    ("-DMULTEE_X86_DEVM", "-DDUMMY2")
  } else {
    ("-DMULTEE_X86_NOSGX", "-DDUMMY2")
  };

  cc::Build::new()
    .files(mbedtls_src_files)
    .include(&mbedtls_include_dir)
    .include(".")
    .flag("-DMBEDTLS_CONFIG_FILE=\"multee_config.h\"")
    .flag(c_def1)
    .flag("-O3")
    // .flag("-mpclmul").flag("-maes") // controls assembly vs c compiler INTRINSICS
    .flag(cpu)
    .compile("mbedcrypto");

  let bindings = bindgen::builder()
    .ctypes_prefix("libc")
    .clang_arg(format!(
      "-I{}",
      mbedtls_include_dir.as_os_str().to_str().unwrap()
    ))
    .clang_arg("-I.")
    .clang_arg(c_def1)
    .header("wrapper.h")
    .derive_default(true)
    .formatter(Formatter::Rustfmt)
    // .rustfmt_bindings(true)
    .derive_debug(true)
    .generate_comments(false)
    .use_core()
    .rustified_enum("mbedtls_md_type_t")
    .rustified_enum("mbedtls_pk_type_t")
    .rustified_enum("mbedtls_cipher_id_t")
    .blocklist_function("mbedtls_aesni_has_support")
    .blocklist_function("mbedtls_internal_.*")
    .blocklist_function("mbedtls_hardware_poll")
    //  vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv following is needed because threading brings stdlib.h, which causes warnings
    .blocklist_function("q.cvt(_r)?")
    .blocklist_function("strtold")
    //  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    .generate()
    .expect("couldn't generate mbedtls bindings");

  let out_dir = env::var_os("OUT_DIR").expect("OUT_DIR env variable is missing");
  let out_dir_path = Path::new(out_dir.as_os_str());
  bindings
    .write_to_file(out_dir_path.join("bindings.rs"))
    .expect("couldn't write mbedtls bindings");

  rerun_if_changed("wrapper.h");
  rerun_if_changed("multee_config.h");
  rerun_if_changed("threading_alt.h");
}
