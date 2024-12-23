pub use kmip::constants::enumerations::CryptographicAlgorithm;
pub use strum::IntoEnumIterator;

pub const MULTEE_GCM_IV_BYTES: usize = 16;
pub const MULTEE_GCM_TAG_BYTES: usize = 16;
pub const MULTEE_BLOCK_SIZE: usize = 16;
pub const MULTEE_AES_KEY_BYTES: usize = 32;
pub const MULTEE_AES_KEY_SIZE: i64 = 256;
pub const MULTEE_HMAC256_BYTES: usize = 32;
pub const MULTEE_RSA_KEY_SIZE: u32 = 2048;
pub const MULTEE_RSA_EXPONENT: i32 = 65537;
pub const MULTEE_SIG_LEN_MAX: usize = 65537;
pub const MAX_CSR_SN_LEN: i64 = 2048;
pub const MULTEE_MAX_KEY_COUNT: usize = 10000;
pub const MAX_MBEDTLS_EMBEDDED_STR_CONST_SIZE: i64 = 16384;
pub const MAX_KMIP_KEY_NAME_LEN: i64 = 512;
pub const MAX_KMIP_KEY_LEN: usize = 3072;
pub const KMIP_RESPONSE_OVERHEAD_HINT: usize = 3072;
pub const KMIP_OVERHEAD_HINT: usize = 384;
pub const MACHINE_KEY_ID: i64 = 1;
pub const MAX_HOSTNAME_LEN: i64 = 256;
pub const MAX_CSR_PEM_LEN: usize = 5120;
pub const MAX_KEY_LEN: usize = 5120;
pub const MAX_KEY_NAME_LEN: usize = 512;
pub const CSR_PASSWD_KEY_BYTES: i64 = 32;
pub const MAX_CA_CHAIN_LEN: i64 = 10;
pub const REMOTE_TTLV_BUFFER_SIZE: usize = 1048576;
pub const MAX_CIPHERTEXT_EXPANSION: usize = MULTEE_BLOCK_SIZE;
pub const GCM_DECRYPT_MIN_OFFSET: usize = 8;

pub const MIN_PAN_LEN: usize = 16;
pub const MAX_PAN_LEN: usize = 20;

pub const MULTEE_KEY_TYPE_AES: u32 = CryptographicAlgorithm::AES as u32;
pub const MULTEE_KEY_TYPE_RSA: u32 = CryptographicAlgorithm::RSA as u32;
pub const MULTEE_KEY_TYPE_ECDSA: u32 = CryptographicAlgorithm::ECDSA as u32;
pub const MULTEE_KEY_TYPE_SM4: u32 = CryptographicAlgorithm::SM4 as u32;

pub const MACHINE_ID_LEN: usize = 128;
pub const SHORT_HASH_LEN: usize = 5; // git default is 28 bits / 3.5 bytes

macro_rules! build_const_enum {
    ($nm:ident : $($con:ident),*) => {
        pub const $nm: &[(&str,i64)] = &[$((stringify!($con),$con as i64)),*];
        };
    }

build_const_enum!( CONST_ENUM : MULTEE_BLOCK_SIZE, MULTEE_GCM_IV_BYTES, MULTEE_GCM_TAG_BYTES, MULTEE_HMAC256_BYTES, MULTEE_SIG_LEN_MAX );
