use atomic_counter::{AtomicCounter, ConsistentCounter};
use log::{debug, error};
use multee_lib::api::EnclaveSession;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use tokio_stream::StreamExt;
use tokio_util::codec::length_delimited;

pub(crate) const MAX_MESSAGE_SIZE_BYTES: usize = 1 << 21;

pub(crate) async fn process(
  socket: TcpStream, socket_addr: SocketAddr, tls_cfg: Arc<ServerConfig>, multee: EnclaveSession,
  counter: Arc<ConsistentCounter>,
) {
  debug!("Connection from: {:?}", socket_addr);

  let key_index_map = multee.key_index_map();

  let tls_config = TlsAcceptor::from(tls_cfg);

  match tls_config.accept(socket).await {
    Err(err) => println!("TLS accept error: {:?}", err),
    Ok(tls) => {
      let certs = tls.get_ref().1.peer_certificates();

      match certs {
        Some(v) => {
          let mut truncated = v[0].clone();
          truncated.0.truncate(10);
          // println!("Cert: {:?}", truncated);
        }
        None => {
          error!(
            "Missing peer certificate. Should be impossible - AllowAnyAuthenticatedClient is set"
          );
          return;
        }
      }

      let (reader, mut writer) = tokio::io::split(tls);

      let reader = length_delimited::Builder::new()
        .length_field_offset(4)
        .length_field_length(4)
        .num_skip(0)
        .length_adjustment(8)
        .max_frame_length(MAX_MESSAGE_SIZE_BYTES) // default is 8MB
        .new_read(reader);

      // TODO: understand why. AsyncRead wants Pin?
      tokio::pin!(reader);

      while let Some(msg) = reader.next().await {
        match msg {
          Err(e) => {
            if e.kind() != ErrorKind::UnexpectedEof {
              error!("Connection produced an error: {}", e);
            } else {
              debug!("Disconnected: {:?}", socket_addr);
            }
            break;
          }
          Ok(buf) => {
            counter.inc();

            match crate::kmip::process_msg(&buf, &multee, &key_index_map) {
              Ok(response) =>
              // Copy the data back to socket
              {
                if let Err(e) = writer.write_all(response.as_slice()).await {
                  // Unexpected socket error. There isn't much we can
                  // do here so just stop processing.
                  eprintln!("Unable to send response: {:?}", e);
                  break;
                }
              }
              Err(e) => {
                // Unexpected protocol error.
                eprintln!("Error: {:?}", e);
                break;
              }
            }
          }
        }
      }
    }
  };
}
