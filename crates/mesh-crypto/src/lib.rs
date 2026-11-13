//! Isolated cryptography crate for Mesh VPN (`SEC-01..SEC-05`).
//!
//! No other crate may directly import low-level cryptographic primitives or manage X.509/SPKI
//! verification logic outside this boundary.

pub mod auth_box;
pub mod certgen;
pub mod disco_box;
pub mod hash;
pub mod keys;
pub mod secret;
pub mod tlspin;

pub use auth_box::{
    ExpectedProofClaims, ProofPayload, SealedAuthProof, open_proof, seal_proof, verify_proof_claims,
};
pub use certgen::{
    GeneratedAcmeCsr, GeneratedTlsIdentity, build_rustls_server_config_from_der,
    build_rustls_server_config_from_pem, build_tls_alpn_certified_key_from_der,
    decode_pkcs8_der_from_keystore, encode_pkcs8_der_for_keystore,
    extract_cert_not_after_ms_from_der, generate_acme_csr_der, generate_ip_pinned_cert,
    generate_tls_alpn_01_challenge_cert, load_certs_from_pem, parse_private_key_from_pem,
    reissue_cert_preserving_key,
};
pub use disco_box::{
    DISCO_INNER_HEADER_LEN, DISCO_OUTER_HEADER_LEN, DISCO_PROTOCOL_VERSION, DiscoRejectReason,
    DiscoSealParams, MIN_DISCO_PACKET_LEN, OpenedDiscoPacket, POLY1305_TAG_LEN, open_disco_packet,
    peek_outer_sender_pubkey, seal_disco_packet,
};
pub use hash::{ct_eq_bytes, sha256_digest, sha256_hex, verify_file_sha256};
pub use keys::{
    DiscoKeypair, NodeKeypair, PreAuthToken, extract_tls_exporter_binding, random_bytes,
};
pub use secret::Secret;
pub use tlspin::{
    PinSet, SpkiPinVerifier, build_pinned_client_config, build_system_ca_client_config,
    classify_rustls_error, extract_spki_pin_from_der,
};
