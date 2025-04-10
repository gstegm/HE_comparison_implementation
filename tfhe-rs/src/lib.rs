/// inspirational sources:
/// https://docs.zama.ai/tfhe-rs/fhe-computation/advanced-features/public_key
/// https://docs.zama.ai/tfhe-rs/fhe-computation/data-handling/serialization
/// https://napi.rs/docs/concepts/values
/// https://www.youtube.com/watch?v=LLxfmrrl4cE

/// import the preludes
use napi::bindgen_prelude::*;
use napi_derive::napi;
use tfhe::{generate_keys, set_server_key, ClientKey, ConfigBuilder, FheInt64, FheBool, ServerKey, CompressedServerKey};
use tfhe::prelude::*;
use tfhe::safe_serialization::{safe_serialize, safe_deserialize};
use tfhe::{PublicKey, CompressedPublicKey};

/// module registration is done by the runtime, no need to explicitly do it now.
/// run $napi build
#[napi]
fn getkeys() -> Vec<Vec<u8>> {
    let config = ConfigBuilder::default().build();

    //let (client_key, server_key) = generate_keys(config);
    //let public_key = PublicKey::new(&client_key);
    let client_key = ClientKey::generate(config);
    let compressed_server_key = CompressedServerKey::new(&client_key);
    let compressed_public_key = CompressedPublicKey::new(&client_key);

    //let mut buffer1 = vec![];
    //safe_serialize(&client_key, &mut buffer1, 1 << 30).unwrap();
    let buffer1 = bincode::serialize(&client_key).unwrap();

    //let mut buffer2 = vec![];
    //safe_serialize(&server_key, &mut buffer2, 1 << 30).unwrap();
    let buffer2 = bincode::serialize(&compressed_server_key).unwrap();

    //let mut buffer3 = vec![];
    //safe_serialize(&public_key, &mut buffer3, 1 << 40).unwrap();
    let buffer3 = bincode::serialize(&compressed_public_key).unwrap();

    return vec![buffer1, buffer2, buffer3];
}

#[napi]
fn enc(clear_a: i64, client_key_buf:Vec<u8>) -> Buffer {
    //let client_key_buf: Vec<u8> = client_key_buf.into();
    //let client_key_deser: ClientKey = safe_deserialize(client_key_buf.as_slice(), 1 << 30).unwrap();
    let client_key_deser: ClientKey = bincode::deserialize(&client_key_buf).unwrap();
   
    let enc_a = FheInt64::encrypt(clear_a, &client_key_deser);

    let mut ctbuf = vec![];
    safe_serialize(&enc_a, &mut ctbuf, 1 << 20).unwrap();

    return ctbuf.into();
}

#[napi]
fn encpub(clear_a: i64, public_key_buf:Vec<u8>) -> Buffer {
    //let public_key_buf: Vec<u8> = public_key_buf.into();
    //let public_key_deser: PublicKey = safe_deserialize(public_key_buf.as_slice(), 1 << 40).unwrap();
    let public_key_compressed: CompressedPublicKey = bincode::deserialize(&public_key_buf).unwrap();
    let public_key: PublicKey = public_key_compressed.decompress();
   
    let enc_a = FheInt64::encrypt(clear_a, &public_key);

    let mut ctbuf = vec![];
    safe_serialize(&enc_a, &mut ctbuf, 1 << 20).unwrap();

    return ctbuf.into();
}

#[napi]
fn gt(enc_a: Buffer, enc_b: Buffer, server_key_buf:Vec<u8>) -> Buffer {
    //let server_key_buf: Vec<u8> = server_key_buf.into();
    let enc_a: Vec<u8> = enc_a.into();
    let enc_b: Vec<u8> = enc_b.into();
    // let config = ConfigBuilder::default().build();
    //let server_key_deser: ServerKey = safe_deserialize(server_key_buf.as_slice(), 1 << 30).unwrap();
    let server_key_compressed: CompressedServerKey = bincode::deserialize(&server_key_buf).unwrap();
    let server_key: ServerKey = server_key_compressed.decompress();
    let enc_a_deser: FheInt64 =
        safe_deserialize(enc_a.as_slice(), 1 << 20).unwrap();
    let enc_b_deser: FheInt64 =
        safe_deserialize(enc_b.as_slice(), 1 << 20).unwrap();
    

    set_server_key(server_key);
    let gtresult = enc_a_deser.gt(enc_b_deser);

    let mut ctbuf = vec![];
    safe_serialize(&gtresult, &mut ctbuf, 1 << 20).unwrap();

    return ctbuf.into();
}

#[napi]
fn dec(enc_a: Buffer, client_key_buf:Vec<u8>) -> bool {
    //let client_key_buf: Vec<u8> = client_key_buf.into();
    let enc_a: Vec<u8> = enc_a.into();
    //let client_key_deser: ClientKey = safe_deserialize(client_key_buf.as_slice(), 1 << 30).unwrap();
    let client_key_deser: ClientKey = bincode::deserialize(&client_key_buf).unwrap();
    let enc_a_deser: FheBool =
        safe_deserialize(enc_a.as_slice(), 1 << 20).unwrap();
       
    let decrypted_bool: bool = enc_a_deser.decrypt(&client_key_deser);

    return decrypted_bool;
}