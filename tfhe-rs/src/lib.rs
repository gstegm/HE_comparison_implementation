/// inspirational sources:
/// https://docs.zama.ai/tfhe-rs/fhe-computation/advanced-features/public_key
/// https://docs.zama.ai/tfhe-rs/fhe-computation/data-handling/serialization
/// https://napi.rs/docs/concepts/values
/// https://www.youtube.com/watch?v=LLxfmrrl4cE

/// import the preludes
use napi::bindgen_prelude::*;
use napi_derive::napi;
use tfhe::{generate_keys, set_server_key, ClientKey, ConfigBuilder, FheInt64, FheBool, ServerKey, CompressedPublicKey, CompressedServerKey};
use tfhe::prelude::*;
use tfhe::safe_serialization::{safe_serialize, safe_deserialize};
use tfhe::PublicKey;
use std::time::Instant;

/// module registration is done by the runtime, no need to explicitly do it now.
/// run $napi build
#[napi]
fn get_keys() -> Vec<Vec<u8>> {
    let config = ConfigBuilder::default().build();
    //let (client_key, server_key) = generate_keys(config);
    let client_key= ClientKey::generate(config);
    let compressed_server_key = CompressedServerKey::new(&client_key);
    let compressed_public_key = CompressedPublicKey::new(&client_key);

    let mut client_key_ser = vec![];
    safe_serialize(&client_key, &mut client_key_ser, 1 << 30).unwrap();
    let mut compressed_server_key_ser = vec![];
    safe_serialize(&compressed_server_key, &mut compressed_server_key_ser, 1 << 30).unwrap();
    let mut compressed_public_key_ser = vec![];
    safe_serialize(&compressed_public_key, &mut compressed_public_key_ser, 1 << 30).unwrap();

    //println!("{}", client_key_ser.len());
    //println!("{}", compressed_server_key_ser.len());
    //println!("{}", compressed_public_key_ser.len());

    return vec![client_key_ser.into(), compressed_server_key_ser.into(), compressed_public_key_ser.into()];
}

#[napi]
fn encrypt(plain: i64, client_key_ser:Vec<u8>) -> Vec<u8> {
    let client_key_ser: Vec<u8> = client_key_ser.into();
    let client_key: ClientKey = safe_deserialize(client_key_ser.as_slice(), 1 << 30).unwrap();
    let cipher = FheInt64::encrypt(plain, &client_key);
    let mut cipher_ser = vec![];
    safe_serialize(&cipher, &mut cipher_ser, 1 << 20).unwrap();

    return cipher_ser.into();
}

#[napi]
fn encrypt_public_key(plain: i64, compressed_public_key_ser:Vec<u8>) -> Vec<u8> {
    let compressed_public_key_ser: Vec<u8> = compressed_public_key_ser.into();
    let compressed_public_key: CompressedPublicKey = safe_deserialize(compressed_public_key_ser.as_slice(), 1 << 35).unwrap();
    let public_key = compressed_public_key.decompress();
   
    let cipher = FheInt64::encrypt(plain, &public_key);
    let mut cipher_ser = vec![];
    safe_serialize(&cipher, &mut cipher_ser, 1 << 20).unwrap();
    return cipher_ser.into();
}

#[napi]
fn greater_than(cipher_a_ser: Vec<u8>, cipher_b_ser: Vec<u8>, compressed_server_key_ser:Vec<u8>) -> Vec<u8> {
    let compressed_server_key_ser: Vec<u8> = compressed_server_key_ser.into();
    let cipher_a_ser: Vec<u8> = cipher_a_ser.into();
    let cipher_b_ser: Vec<u8> = cipher_b_ser.into();
    //let server_key: CompressedServerKey = safe_deserialize(server_key_ser.as_slice(), 1 << 30).unwrap();
    let compressed_server_key: CompressedServerKey = safe_deserialize(compressed_server_key_ser.as_slice(), 1 << 30).unwrap();
    let cipher_a: FheInt64 = safe_deserialize(cipher_a_ser.as_slice(), 1 << 20).unwrap();
    let cipher_b: FheInt64 = safe_deserialize(cipher_b_ser.as_slice(), 1 << 20).unwrap();

    //let gpu_key = server_key.decompress_to_gpu();
    let server_key = compressed_server_key.decompress();
    //set_server_key(gpu_key);
    set_server_key(server_key);

    let now = Instant::now();
    let gtresult = cipher_a.gt(cipher_b.clone());
    let elapsed = now.elapsed();
    //println!("Elapsed: {:.2?}", elapsed);
    let mut gtresult_ser = vec![];
    safe_serialize(&gtresult, &mut gtresult_ser, 1 << 20).unwrap();

    return gtresult_ser.into();
}

#[napi]
fn decrypt(cipher_ser: Vec<u8>, client_key_ser:Vec<u8>) -> bool {
    let client_key_ser: Vec<u8> = client_key_ser.into();
    let cipher_ser: Vec<u8> = cipher_ser.into();

    let client_key: ClientKey = safe_deserialize(client_key_ser.as_slice(), 1 << 30).unwrap();
    let cipher: FheBool = safe_deserialize(cipher_ser.as_slice(), 1 << 20).unwrap();
       
    let plain: bool = cipher.decrypt(&client_key);
    return plain;
}

/* 
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

    // Scope the large key structs so they get dropped early
    let (client_key_ser, server_key_ser, public_key_ser) = {
        let (client_key, server_key) = generate_keys(config);
        let public_key = PublicKey::new(&client_key);

        // Serialize them while still in scope
        let client_key_ser = bincode::serialize(&client_key).unwrap();
        let server_key_ser = bincode::serialize(&server_key).unwrap();
        let public_key_ser = bincode::serialize(&public_key).unwrap();

        // After this block, client_key, server_key, and public_key are dropped
        (client_key_ser, server_key_ser, public_key_ser)
    };

    // Now only serialized buffers are in scope (smaller memory footprint)
    vec![
        client_key_ser.into(),
        server_key_ser.into(),
        public_key_ser.into(),
    ]
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

*/