//! Tests for the FLOE streaming-encryption file source proposed for MSC4016.
//!
//! These prove that a classic `m.room.message` with `msgtype: m.file` carrying a FLOE `file`
//! block deserializes as *typed media* — `MediaSource::Encrypted` selecting the `Floe` variant of
//! `EncryptedFileInfo` — rather than failing to parse for want of the (v2-only) `hashes` field.

#![cfg(feature = "unstable-msc4016")]

use assert_matches2::assert_matches;
use js_int::uint;
use ruma_common::canonical_json::assert_to_canonical_json_eq;
use ruma_events::room::{
    EncryptedFile, EncryptedFileInfo, MediaSource, message::FileMessageEventContent,
};
use serde_json::{from_value as from_json_value, json};

/// A representative FLOE `file` block as a client emits it: a JWK-wrapped 256-bit root key, the
/// segment size and plaintext length, and the FLOE `v` discriminator — with no `iv` and no
/// `hashes` (FLOE authenticates each segment in place).
fn floe_file_json() -> serde_json::Value {
    json!({
        "url": "mxc://notareal.hs/hugefloefile",
        "key": {
            "kty": "oct",
            "key_ops": ["decrypt", "encrypt"],
            "alg": "FLOE-A256GCM-SHA384",
            "k": "TLlG_OpX807zzQuuwv4QZGJ21_u7weemFGYJFszMn9A",
            "ext": true
        },
        "enc_seg_len": 262_144,
        "size": 4_294_967_296_u64,
        "v": "org.matrix.msc4016.floe.v0"
    })
}

#[test]
fn floe_encrypted_file_deserialization() {
    let file = from_json_value::<EncryptedFile>(floe_file_json()).unwrap();

    assert_eq!(file.url, "mxc://notareal.hs/hugefloefile");
    // FLOE carries no whole-file ciphertext hash.
    assert!(file.hashes.is_empty());

    assert_matches!(&file.info, EncryptedFileInfo::Floe(info));
    assert_eq!(info.key.encode(), "TLlG_OpX807zzQuuwv4QZGJ21_u7weemFGYJFszMn9A");
    assert_eq!(info.enc_seg_len, uint!(262_144));
    assert_eq!(u64::from(info.size), 4_294_967_296);
    assert_eq!(file.info.version(), "org.matrix.msc4016.floe.v0");
}

#[test]
fn floe_file_message_is_typed_media() {
    // A classic m.room.message (msgtype m.file) whose `file` block is FLOE. Before this change
    // ruma rejected it (required `hashes`), surfacing as a parse failure; now it deserializes as
    // typed media so a client never has to reach into the raw event JSON.
    let content = from_json_value::<FileMessageEventContent>(json!({
        "body": "hugefile.bin",
        "filename": "hugefile.bin",
        "info": { "mimetype": "application/octet-stream", "size": 4_294_967_296_u64 },
        "file": floe_file_json(),
    }))
    .unwrap();

    assert_eq!(content.body, "hugefile.bin");
    assert_matches!(content.source, MediaSource::Encrypted(file));
    assert_matches!(&file.info, EncryptedFileInfo::Floe(info));
    assert_eq!(u64::from(info.size), 4_294_967_296);
}

#[test]
fn floe_encrypted_file_round_trip() {
    // Serializing back yields the same block: the FLOE JWK is reconstructed and neither `iv` nor
    // `hashes` is emitted.
    let file = from_json_value::<EncryptedFile>(floe_file_json()).unwrap();
    assert_to_canonical_json_eq!(file, floe_file_json());
}
