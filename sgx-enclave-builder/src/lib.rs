use cc;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

pub struct BuildEnvironment {
  intel_sdk: PathBuf,
  teaclave_sdk: PathBuf,
  out_dir: PathBuf,
  version_script_lds: PathBuf,
  enclave_config_xml: PathBuf,
}

impl BuildEnvironment {
  pub fn new(
    sgx_sdk: &str, rust_sgx_sdk: &str, out_dir: &str, version_script_lds: &str,
    enclave_config_xml: &str,
  ) -> Self {
    BuildEnvironment {
      intel_sdk: PathBuf::from(sgx_sdk),
      teaclave_sdk: PathBuf::from(rust_sgx_sdk),
      out_dir: PathBuf::from(out_dir),
      version_script_lds: PathBuf::from(version_script_lds),
      enclave_config_xml: PathBuf::from(enclave_config_xml),
    }
  }

  pub fn compile_untrusted_edl(&self, edl_file: &str) {
    let (gen_u_c, gen_u_h) = self.edger8(edl_file, "untrusted");
    cc::Build::new()
      .file(&gen_u_c)
      .include(gen_u_h.parent().unwrap())
      .include(self.teaclave_sdk.join("sgx_edl").join("edl"))
      .include(self.intel_sdk.join("include"))
      .flag("-Wno-attributes")
      .compile("enclave_u_api");
  }

  pub fn compile_trusted_edl(&self, edl_file: &str) -> PathBuf {
    let (gen_t_c, gen_t_h) = self.edger8(edl_file, "trusted");
    cc::Build::new()
      .file(gen_t_c)
      .include(gen_t_h.parent().unwrap())
      // .include("/usr/include")
      .include(self.teaclave_sdk.join("common/inc"))
      .include(self.teaclave_sdk.join("common/inc/tlibc"))
      .include(self.teaclave_sdk.join("sgx_edl").join("edl"))
      .include(self.intel_sdk.join("include"))
      .include(self.intel_sdk.join("include/tlibc"))
      .include(self.intel_sdk.join("include/stlport"))
      .include(self.intel_sdk.join("include/epid"))
      .flag("-nostdinc")
      .flag("-fvisibility=hidden")
      .flag("-fstack-protector")
      .flag("-Wno-implicit-function-declaration") // TODO: remove once Intel cleans it's includes
      .out_dir(self.out_dir.as_path())
      .cargo_metadata(false)
      .compile("enclave_t_api");

    self.out_dir.join("libenclave_t_api.a")
  }

  pub fn link_enclave(
    &self, enclave_t_impl: &str, trusted_edl_api: &PathBuf, suffix: &str,
  ) -> PathBuf {
    let _trts_lib = format!("sgx_trts{}", suffix);
    let tservice_lib = format!("sgx_tservice{}", suffix);
    let enclave_out = self.out_dir.join(format!("enclave{}.so", suffix));

    let args = format!(
      "-o {} -O2 -m64
              -Wl,-z,relro,-z,now,-z,noexecstack
              -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L{}
              -Wl,--whole-archive -lsgx_tswitchless -lsgx_pthread  {} -Wl,--no-whole-archive
              -Wl,--start-group  -lsgx_tcrypto  -l{} {} -Wl,--end-group
              -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined
              -Wl,-pie,-eenclave_entry -Wl,--export-dynamic
              -Wl,--gc-sections -Wl,--defsym,__ImageBase=0
              -Wl,--version-script={}",
      enclave_out.display(),
      self.intel_sdk.join("lib64").display(),
      // trts_lib, // trts is now part of teaclave. tstdc too?
      trusted_edl_api.display(),
      tservice_lib,
      enclave_t_impl,
      self.version_script_lds.display(),
    );

    Command::new("cc").args(args.split_whitespace()).exec();

    enclave_out
  }

  pub fn sgx_sign_dev(&self, unsigned_enclave: PathBuf, signing_key: &str) -> PathBuf {
    let signed_enclave = self
      .out_dir
      .join(unsigned_enclave.file_name().unwrap())
      .with_extension("so.signed");
    let args = format!(
      "sign -key {} -enclave {} -config {} -out {}",
      signing_key,
      unsigned_enclave.display(),
      self.enclave_config_xml.display(),
      signed_enclave.display()
    );

    Command::new(self.intel_sdk.join("bin/x64/sgx_sign"))
      .args(args.split_whitespace())
      .exec();

    signed_enclave
  }

  pub fn sgx_sign_prod(&self, enclave: PathBuf, public_key: &str) -> PathBuf {
    let enclave_hash = self.sgx_sign_gendata(enclave.clone(), &self.enclave_config_xml);
    let signed_enclave_hash = self.sign_enclave_hash(enclave_hash.clone());
    self.sgx_sign_catsig(
      enclave,
      &self.enclave_config_xml,
      public_key,
      enclave_hash,
      signed_enclave_hash,
    )
  }

  fn sgx_sign_gendata(&self, unsigned_enclave: PathBuf, enclave_config_xml: &PathBuf) -> PathBuf {
    let sgx_sign = self.intel_sdk.join("bin/x64/sgx_sign");
    let enclave_hash = self.out_dir.join("enclave_hash.hex");

    let args = format!(
      "gendata -enclave {} -config {} -out {}",
      unsigned_enclave.display(),
      enclave_config_xml.display(),
      enclave_hash.display(),
    );

    Command::new(sgx_sign).args(args.split_whitespace()).exec();

    enclave_hash
  }

  fn sgx_sign_catsig(
    &self, unsigned_enclave: PathBuf, enclave_config_xml: &PathBuf, public_key: &str,
    enclave_hash: PathBuf, signed_enclave_hash: PathBuf,
  ) -> PathBuf {
    let sgx_sign = self.intel_sdk.join("bin/x64/sgx_sign");
    let signed_enclave = self
      .out_dir
      .join(unsigned_enclave.file_name().unwrap())
      .with_extension("so.signed");

    let args = format!(
      "catsig -enclave {} -config {} -key {} -unsigned {} -sig {} -out {}",
      unsigned_enclave.display(),
      enclave_config_xml.display(),
      public_key,
      enclave_hash.display(),
      signed_enclave_hash.display(),
      signed_enclave.display(),
    );

    Command::new(sgx_sign).args(args.split_whitespace()).exec();

    signed_enclave
  }

  fn sign_enclave_hash(&self, enclave_hash: PathBuf) -> PathBuf {
    let signed_enclave_hash = enclave_hash.with_extension("hex.signed");

    // TODO: implement signing
    // signEnclaveHash -PenclaveHash=untrusted/target/debug/build/untrusted-sgx-xxxxxxxxxxxxxx/out/enclave_hash.hex

    signed_enclave_hash
  }

  fn edger8(&self, edl_file: &str, kind: &str) -> (PathBuf, PathBuf) {
    let edl_file = PathBuf::from(edl_file);
    let sgx_edger8r = self.intel_sdk.join("bin/x64/sgx_edger8r");

    let search_paths = format!(
      "--search-path {} --search-path {}",
      self.intel_sdk.join("include").display(),
      self.teaclave_sdk.join("sgx_edl").join("edl").display()
    );

    let args = format!(
      "--{} {} --{}-dir {}",
      kind,
      edl_file.display(),
      kind,
      self.out_dir.display()
    );

    Command::new(sgx_edger8r.as_path())
      .args(args.split_whitespace())
      .args(search_paths.split_whitespace())
      .exec();

    let file_stem = self.out_dir.join(format!(
      "{}_{}",
      edl_file.file_stem().unwrap().to_str().unwrap(),
      &kind[..1]
    ));
    (file_stem.with_extension("c"), file_stem.with_extension("h"))
  }
}

pub trait CommandExecutor {
  fn exec(&mut self);
}

impl CommandExecutor for Command {
  fn exec(&mut self) {
    let output = self.output().unwrap();
    std::io::stdout().write_all(&output.stdout).unwrap();
    std::io::stderr().write_all(&output.stderr).unwrap();
    assert!(output.status.success());
  }
}
