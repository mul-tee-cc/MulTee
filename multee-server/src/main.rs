use atomic_counter::{AtomicCounter, ConsistentCounter};
use clap::{App, Arg};
use log::info;
use multee_lib::api::EnclaveSession;
use rustls_pemfile::{certs, ec_private_keys, pkcs8_private_keys, rsa_private_keys};
use std::fs::File;
use std::io::BufReader;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::time::{sleep, Duration};
use tokio_rustls::rustls::server::AllowAnyAuthenticatedClient;
use tokio_rustls::rustls::{Certificate, PrivateKey, RootCertStore, ServerConfig};
use tokio_task_pool::Pool;

mod kmip;
mod srv;

fn app() -> App<'static, 'static> {
  App::new("multee-server")
    .about("MulTee KMIP server example")
    .arg(Arg::with_name("addr").value_name("ADDR").required(true))
    .arg(
      Arg::with_name("auth-cert")
        .short("ac")
        .long("auth-cert")
        .value_name("FILE")
        .help("client auth cert file.")
        .required(true),
    )
    .arg(
      Arg::with_name("cert")
        .short("c")
        .long("cert")
        .value_name("FILE")
        .help("TLS cert file.")
        .required(true),
    )
    .arg(
      Arg::with_name("key")
        .short("k")
        .long("key")
        .value_name("FILE")
        .help("TLS key file, rsa only.")
        .required(true),
    )
    .arg(
      Arg::with_name("literals")
        .short("l")
        .long("literals")
        .value_name("FILE")
        .help("literal keys")
        .required(true),
    )
    .arg(
      Arg::with_name("literal_keynames")
        .short("K")
        .long("keynames")
        .value_name("key1,Key2,...")
        .help("literal key names")
        .required(true),
    )
}

#[tokio::main(flavor = "multi_thread", worker_threads = 16)]
// #[tokio::main(worker_threads=16)]
// #[tokio::main]
async fn main() {
  env_logger::init();
  let matches = app().get_matches();

  let addr = matches
    .value_of("addr")
    .unwrap()
    .to_socket_addrs()
    .unwrap()
    .next()
    .unwrap();

  let auth_file = matches.value_of("auth-cert").unwrap();
  let cert_file = matches.value_of("cert").unwrap();
  let key_file = matches.value_of("key").unwrap();
  let literals = matches.value_of("literals").unwrap();
  let key_names = matches.value_of("literal_keynames").unwrap();
  let key_names: Vec<String> = key_names
    .split(",")
    .into_iter()
    .map(str::to_string)
    .collect();

  let multee = EnclaveSession::load_keys(literals, "file://./", key_names, None).unwrap();

  let mut client_auth_roots = RootCertStore::empty();

  for cert in load_certs(auth_file) {
    client_auth_roots.add(&cert).unwrap();
  }
  let client_auth_vfy = AllowAnyAuthenticatedClient::new(client_auth_roots);

  let key = load_key(key_file);

  let config = ServerConfig::builder()
    .with_safe_defaults()
    .with_client_cert_verifier(Arc::new(client_auth_vfy))
    .with_single_cert(load_certs(cert_file), key)
    .expect("invalid key or certificate");

  let srv = TcpListener::bind(&addr).await.unwrap();

  let tls_cfg = Arc::new(config);

  // let pool = Pool::unbounded();
  let pool = Pool::bounded(16);
  //   .with_spawn_timeout(Duration::from_secs(2))
  // .with_run_timeout(Duration::from_secs(1))

  let cpu_pool = tokio::runtime::Builder::new_multi_thread()
    .worker_threads(8)
    .build()
    .unwrap();

  let counter = Arc::new(ConsistentCounter::new(0));

  print_metrics(counter.clone());

  info!("Listening for connections on {}", addr);
  loop {
    let counter = counter.clone();
    let (socket, socket_addr) = srv.accept().await.unwrap();
    let tls_cfg = tls_cfg.clone();
    let multee = multee.clone();
    pool
      .spawn(async move {
        srv::process(socket, socket_addr, tls_cfg, multee, counter).await;
      })
      .await
      .unwrap();
    // cpu_pool.spawn(async move {
    //   srv::process(socket, socket_addr, tls_cfg, multee, counter).await;
    // });
  }
}

fn print_metrics(counter: Arc<ConsistentCounter>) {
  tokio::spawn(async move {
    let mut prev = counter.get();
    loop {
      sleep(Duration::from_secs(5)).await;
      let new = counter.get();
      let diff = new - prev;
      prev = new;
      info!("{} messages in 5s, avg {}/s", diff, diff / 5);
    }
  });
}

fn load_certs(path: &str) -> Vec<Certificate> {
  certs(&mut BufReader::new(File::open(path).unwrap()))
    .unwrap()
    .into_iter()
    .map(Certificate)
    .collect()
}

type PKParser = dyn Fn(&mut dyn std::io::BufRead) -> Result<Vec<Vec<u8>>, std::io::Error>;

fn try_load_key(loader: &PKParser, path: &str) -> Result<Vec<PrivateKey>, std::io::Error> {
  Ok(
    loader(&mut BufReader::new(File::open(path)?))?
      .into_iter()
      .map(PrivateKey)
      .collect(),
  )
}

fn load_key(path: &str) -> PrivateKey {
  let loaders = [pkcs8_private_keys, rsa_private_keys, ec_private_keys];

  for l in loaders {
    match try_load_key(&l, path) {
      Ok(mut v) if !v.is_empty() => return v.remove(0),
      _ => continue,
    }
  }
  panic!("Unable to load TLS private key");
}
