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
use std::mem;

/// module registration is done by the runtime, no need to explicitly do it now.
/// run $napi build
#[napi]
fn getkeys() -> Vec<Buffer> {
    let config = ConfigBuilder::default().build();

    let (client_key, server_key) = generate_keys(config);
    let public_key = PublicKey::new(&client_key);

    let mut client_key_ser = vec![];
    safe_serialize(&client_key, &mut client_key_ser, 1 << 30).unwrap();
    let mut server_key_ser = vec![];
    safe_serialize(&server_key, &mut server_key_ser, 1 << 30).unwrap();
    let mut public_key_ser = vec![];
    safe_serialize(&public_key, &mut public_key_ser, 1 << 35).unwrap();

    drop(client_key);
    drop(server_key);
    drop(public_key);

    return vec![client_key_ser.into(), server_key_ser.into(), public_key_ser.into()];
}

#[napi]
fn enc(plain: i64, client_key_ser:Buffer) -> Buffer {
    let client_key_ser: Vec<u8> = client_key_ser.into();
    let client_key: ClientKey = safe_deserialize(client_key_ser.as_slice(), 1 << 30).unwrap();
   
    let cipher = FheInt64::encrypt(plain, &client_key);
    let mut cipher_ser = vec![];
    safe_serialize(&cipher, &mut cipher_ser, 1 << 20).unwrap();

    return cipher_ser.into();
}

#[napi]
fn encpub(plain: i64, public_key_ser:Buffer) -> Buffer {
    let public_key_ser: Vec<u8> = public_key_ser.into();
    let public_key: PublicKey = safe_deserialize(public_key_ser.as_slice(), 1 << 40).unwrap();
   
    let cipher = FheInt64::encrypt(plain, &public_key);
    let mut cipher_ser = vec![];
    safe_serialize(&cipher, &mut cipher_ser, 1 << 20).unwrap();
    return cipher_ser.into();
}

#[napi]
fn gt(cipher_a_ser: Buffer, cipher_b_ser: Buffer, server_key_ser:Buffer) -> Buffer {
    let server_key_ser: Vec<u8> = server_key_ser.into();
    let cipher_a_ser: Vec<u8> = cipher_a_ser.into();
    let cipher_b_ser: Vec<u8> = cipher_b_ser.into();
    let server_key: ServerKey = safe_deserialize(server_key_ser.as_slice(), 1 << 30).unwrap();
    let cipher_a: FheInt64 = safe_deserialize(cipher_a_ser.as_slice(), 1 << 20).unwrap();
    let cipher_b: FheInt64 = safe_deserialize(cipher_b_ser.as_slice(), 1 << 20).unwrap();

    set_server_key(server_key.clone());
    println!("start");
    let gtresult = cipher_a.gt(cipher_b.clone());
    println!("end");

    let mut gtresult_ser = vec![];
    safe_serialize(&gtresult, &mut gtresult_ser, 1 << 20).unwrap();

    return gtresult_ser.into();
}

#[napi]
fn dec(cipher_ser: Buffer, client_key_ser:Buffer) -> bool {
    let client_key_ser: Vec<u8> = client_key_ser.into();
    let cipher_ser: Vec<u8> = cipher_ser.into();

    let client_key: ClientKey = safe_deserialize(client_key_ser.as_slice(), 1 << 30).unwrap();
    let cipher: FheBool = safe_deserialize(cipher_ser.as_slice(), 1 << 20).unwrap();
       
    let plain: bool = cipher.decrypt(&client_key);
    return plain;
}

#[napi]
fn all_in_one() {
        let config = ConfigBuilder::default().build();

        let (client_key, server_key) = generate_keys(config);
        let public_key = PublicKey::new(&client_key);
        let client_key_ser = bincode::serialize(&client_key).unwrap();
        let server_key_ser = bincode::serialize(&server_key).unwrap();
        let public_key_ser = bincode::serialize(&public_key).unwrap();

        let client_key1: ClientKey = bincode::deserialize(&client_key_ser).unwrap();
        let server_key1: ServerKey = bincode::deserialize(&server_key_ser).unwrap();
        let public_key1: PublicKey = bincode::deserialize(&public_key_ser).unwrap();


        let plain_a: i64 = 1744829708;
        let plain_b: i64 = 1744829724;
   
        let cipher_a = FheInt64::encrypt(plain_a, &client_key1);
        let cipher_b = FheInt64::encrypt(plain_b, &public_key1);
        set_server_key(server_key1);
        let gtresult = cipher_a.clone().gt(cipher_b.clone());
        let plain: bool = gtresult.decrypt(&client_key);
        println!("{}", plain);
}

#[napi]
fn get_keys() -> Vec<Buffer> {
    let config = ConfigBuilder::default().build();

    let (client_key, server_key) = generate_keys(config);
    let public_key = PublicKey::new(&client_key);

    let client_key_ser = bincode::serialize(&client_key).unwrap();
    let server_key_ser = bincode::serialize(&server_key).unwrap();
    let public_key_ser = bincode::serialize(&public_key).unwrap();

    return vec![client_key_ser.into(), server_key_ser.into(), public_key_ser.into()];
}

#[napi]
fn encrypt(plain: i64, client_key_ser:Buffer) -> Buffer {
    let client_key_ser: Vec<u8> = client_key_ser.into();
    let client_key: ClientKey = bincode::deserialize(&client_key_ser).unwrap();
   
    let cipher = FheInt64::encrypt(plain, &client_key);
    let cipher_ser = bincode::serialize(&cipher).unwrap();

    return cipher_ser.into();
}

#[napi]
fn encrypt_public_key(plain: i64, public_key_ser:Buffer) -> Buffer {
    let public_key_ser: Vec<u8> = public_key_ser.into();
    let public_key: PublicKey = bincode::deserialize(&public_key_ser).unwrap();
   
    let cipher = FheInt64::encrypt(plain, &public_key);
    let cipher_ser = bincode::serialize(&cipher).unwrap();
    return cipher_ser.into();
}

#[napi]
fn greater_than(cipher_a_ser: Buffer, cipher_b_ser: Buffer, server_key_ser:Buffer) -> Buffer {
    let server_key_ser: Vec<u8> = server_key_ser.into();
    let cipher_a_ser: Vec<u8> = cipher_a_ser.into();
    let cipher_b_ser: Vec<u8> = cipher_b_ser.into();
    let server_key: ServerKey = bincode::deserialize(&server_key_ser).unwrap();
    let cipher_a: FheInt64 = bincode::deserialize(&cipher_a_ser).unwrap();
    let cipher_b: FheInt64 = bincode::deserialize(&cipher_b_ser).unwrap();

    set_server_key(server_key.clone());
    println!("start");
    let gtresult: FheBool = cipher_a.gt(cipher_b.clone());
    println!("end");

    let gtresult_ser: Vec<u8> = bincode::serialize(&gtresult).unwrap();

    return gtresult_ser.into();
}

#[napi]
fn decrypt(cipher_ser: Buffer, client_key_ser:Buffer) -> bool {
    let client_key_ser: Vec<u8> = client_key_ser.into();
    let cipher_ser: Vec<u8> = cipher_ser.into();

    let client_key: ClientKey = bincode::deserialize(&client_key_ser).unwrap();
    let cipher: FheBool = bincode::deserialize(&cipher_ser).unwrap();
       
    let plain: bool = cipher.decrypt(&client_key);
    return plain;
}