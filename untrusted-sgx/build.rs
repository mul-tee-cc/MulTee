use enclave_builder::BuildEnvironment;
use std::env;

fn main() {
  let out_dir = env::var("OUT_DIR").expect("impossible - build error");
  let intel_sdk = env::var("SGX_SDK").expect("impossible - build error");
  let teaclave_sdk = env::current_dir()
    .expect("impossible - build error")
    .parent()
    .expect("impossible - build error")
    .join("deps")
    .join("incubator-teaclave-sgx-sdk")
    .into_os_string();
  let profile = env::var("PROFILE").expect("impossible - build error");
  let rust_sgx_sdk = teaclave_sdk.to_str().expect("impossible - build error");
  let edl_file = "../trusted-sgx/resources/multee.edl";
  let signing_key = "../trusted-sgx/resources/multee-private.pem";
  let public_key = "../trusted-sgx/resources/multee-signing-cert.pem";
  let version_script_lds = "../trusted-sgx/resources/multee.lds";
  let enclave_config_xml = "../trusted-sgx/resources/multee-config.xml";

  let env = BuildEnvironment::new(
    intel_sdk.as_str(),
    rust_sgx_sdk,
    out_dir.as_str(),
    version_script_lds,
    enclave_config_xml,
  );

  env.compile_untrusted_edl(edl_file);
  let trusted_edl_lib = env.compile_trusted_edl(edl_file);

  let enclave_t_impl = format!(
    "../trusted-sgx/target/x86_64-unknown-linux-sgx/{}/libtrusted_sgx.a",
    profile
  );
  // TODO: separate sysroot
  let enclave = env.link_enclave(enclave_t_impl.as_str(), &trusted_edl_lib, "");
  let sim_enclave = env.link_enclave(enclave_t_impl.as_str(), &trusted_edl_lib, "_sim");

  let signed_sim_enclave = env.sgx_sign_dev(sim_enclave, signing_key);

  let signed_enclave = if cfg!(feature = "prod-signing") && false {
    env.sgx_sign_prod(enclave, public_key)
  } else {
    env.sgx_sign_dev(enclave, signing_key)
  };

  println!(""); // build output noise separator, otherwise next println might be ignored
  println!(
    "cargo:rustc-env=SIGNED_ENCLAVE_SIM_PATH={}",
    signed_sim_enclave.display()
  );
  println!(
    "cargo:rustc-env=SIGNED_ENCLAVE_PATH={}",
    signed_enclave.display()
  );

  // panic!();
  println!("cargo:rustc-link-search=native={}/lib64", intel_sdk);
  println!("cargo:rustc-link-lib=dylib=sgx_dcap_ql");
  println!("cargo:rustc-link-lib=dylib=sgx_urts");

  println!("cargo:rerun-if-changed={}", edl_file);
  println!("cargo:rerun-if-changed={}", enclave_t_impl);
  println!("cargo:rerun-if-changed={}", version_script_lds);
  println!("cargo:rerun-if-changed={}", signing_key);
  println!("cargo:rerun-if-changed={}", public_key);
  println!("cargo:rerun-if-changed={}", enclave_config_xml);
  // panic!();
}
