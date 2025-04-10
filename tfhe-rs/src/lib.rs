/// inspirational sources:
/// https://docs.zama.ai/tfhe-rs/fhe-computation/advanced-features/public_key
/// https://docs.zama.ai/tfhe-rs/fhe-computation/data-handling/serialization
/// https://napi.rs/docs/concepts/values
/// https://www.youtube.com/watch?v=LLxfmrrl4cE

/// import the preludes
use napi::bindgen_prelude::*;
use napi_derive::napi;
use tfhe::{generate_keys, set_server_key, ClientKey, ConfigBuilder, FheInt64, FheBool, ServerKey};
use tfhe::prelude::*;
use tfhe::safe_serialization::{safe_serialize, safe_deserialize};
use tfhe::PublicKey;

/// module registration is done by the runtime, no need to explicitly do it now.
/// run $napi build
#[napi]
fn getkeys() -> Vec<Buffer> {
    let config = ConfigBuilder::default().build();

    let (client_key, server_key) = generate_keys(config);
    let public_key = PublicKey::new(&client_key);

    let mut buffer1 = vec![];
    safe_serialize(&client_key, &mut buffer1, 1 << 30).unwrap();

    let mut buffer2 = vec![];
    safe_serialize(&server_key, &mut buffer2, 1 << 30).unwrap();

    let mut buffer3 = vec![];
    safe_serialize(&public_key, &mut buffer3, 1 << 40).unwrap();

    return vec![buffer1.into(), buffer2.into(), buffer3.into()];
}

#[napi]
fn enc(clear_a: i64, client_key_buf:Buffer) -> Buffer {
    let client_key_buf: Vec<u8> = client_key_buf.into();
    let client_key_deser: ClientKey =
        safe_deserialize(client_key_buf.as_slice(), 1 << 30).unwrap();
   
    let enc_a = FheInt64::encrypt(clear_a, &client_key_deser);

    let mut ctbuf = vec![];
    safe_serialize(&enc_a, &mut ctbuf, 1 << 20).unwrap();

    return ctbuf.into();
}

#[napi]
fn encpub(clear_a: i64, public_key_buf:Buffer) -> Buffer {
    let public_key_buf: Vec<u8> = public_key_buf.into();
    let public_key_deser: PublicKey =
        safe_deserialize(public_key_buf.as_slice(), 1 << 40).unwrap();
   
    let enc_a = FheInt64::encrypt(clear_a, &public_key_deser);

    let mut ctbuf = vec![];
    safe_serialize(&enc_a, &mut ctbuf, 1 << 20).unwrap();

    return ctbuf.into();
}

#[napi]
fn gt(enc_a: Buffer, enc_b: Buffer, server_key_buf:Buffer) -> Buffer {
    let server_key_buf: Vec<u8> = server_key_buf.into();
    let enc_a: Vec<u8> = enc_a.into();
    let enc_b: Vec<u8> = enc_b.into();
    // let config = ConfigBuilder::default().build();
    let server_key_deser: ServerKey =
        safe_deserialize(server_key_buf.as_slice(), 1 << 30).unwrap();
    let enc_a_deser: FheInt64 =
        safe_deserialize(enc_a.as_slice(), 1 << 20).unwrap();
    let enc_b_deser: FheInt64 =
        safe_deserialize(enc_b.as_slice(), 1 << 20).unwrap();
    

    set_server_key(server_key_deser);
    let gtresult = enc_a_deser.gt(enc_b_deser);

    let mut ctbuf = vec![];
    safe_serialize(&gtresult, &mut ctbuf, 1 << 20).unwrap();

    return ctbuf.into();
}

#[napi]
fn dec(enc_a: Buffer, client_key_buf:Buffer) -> bool {
    let client_key_buf: Vec<u8> = client_key_buf.into();
    let enc_a: Vec<u8> = enc_a.into();
    let client_key_deser: ClientKey =
        safe_deserialize(client_key_buf.as_slice(), 1 << 30).unwrap();
    let enc_a_deser: FheBool =
        safe_deserialize(enc_a.as_slice(), 1 << 20).unwrap();
       
    let decrypted_bool: bool = enc_a_deser.decrypt(&client_key_deser);

    return decrypted_bool;
}