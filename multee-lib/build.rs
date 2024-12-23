use std::fs;
use std::io::{self, Write};
use std::ops::Add;
use std::process::Command;
use std::time::Duration;

fn main() {
  // TODO: revisit
  if false {
    let ten_min = Duration::from_secs(600);
    let mod_time = fs::metadata("../test-data/id-credentials.zip").and_then(|x| x.modified());
    match mod_time {
      Ok(time) if time.add(ten_min) > std::time::SystemTime::now() => {
        println!("modtime: {:?}", mod_time)
      }
      _ => {
        println!("cargo:warning=creating zip ../test-data/id-credentials.zip");
        let output = Command::new("pwd")
          .current_dir("../test-data")
          .output()
          .expect("failed hard");
        println!("pwd status: {}", output.status);
        io::stdout()
          .write_all(&output.stdout)
          .expect("impossible - build error");
        io::stderr()
          .write_all(&output.stderr)
          .expect("impossible - build error");
        let output = Command::new("zip")
          .current_dir("../test-data")
          .args(&[
            "id-credentials.zip",
            "MANIFEST.YAML",
            "ca-chain.pem",
            "client.crt",
            "client.key",
            "client.req",
            "TestKey.aes",
            "TestKey.rsa",
            "TestKey.ecc",
            "TlsKey.rsa",
            "TlsKey.ecc",
          ])
          .output()
          .expect("failed to create zip");
        println!("zip status: {}", output.status);
        io::stdout()
          .write_all(&output.stdout)
          .expect("impossible - build error");
        io::stderr()
          .write_all(&output.stderr)
          .expect("impossible - build error");
      }
    }
  }
}
