// #![feature(option_result_contains)]

pub mod api;
mod credentials;
mod err;
mod literal;
mod remote_kmip;
mod util;
mod yaml;
// mod remote_kmip;
// mod remote;

#[allow(dead_code)]
static MULTEE_VERSION: &str =
  const_format::formatcp!("$Revision: MulTee {} $", env!("CARGO_PKG_VERSION"));

const DLL: &[u8] = include_bytes!("../../untrusted-sgx/target/debug/libuntrusted_sgx.so");
#[cfg(feature = "with-dcap")]
mod dcap_test_blobs {
  pub const URTS_SIM: &[u8] = include_bytes!("/opt/intel/sgxsdk/lib64/libsgx_urts_sim.so");
  pub const UAE_SIM: &[u8] = include_bytes!("/opt/intel/sgxsdk/lib64/libsgx_uae_service_sim.so");
  pub const PCE_LOGIC: &[u8] = include_bytes!("/usr/lib64/libsgx_pce_logic.so");
  pub const QE3_LOGIC: &[u8] = include_bytes!("/usr/lib64/libsgx_qe3_logic.so");
  pub const DCAP_QL: &[u8] = include_bytes!("/usr/lib64/libsgx_dcap_ql.so.1");
}
#[cfg(feature = "with-sevsnp")]
mod sevsnp_test_blobs {
  pub const DUMMY_SNP_REPORT: &[u8] = include_bytes!("../resources/report_milan.bin");
  pub const DUMMY_SNP_VCEK_MILAN: &[u8] = include_bytes!("../resources/vcek_milan.der");
  pub const DUMMY_SNP_INT_MILAN: &str = include_str!("../resources/intermediate_milan.pem");
}
