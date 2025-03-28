/// import the preludes
use napi::bindgen_prelude::*;
use napi_derive::napi;
use tfhe::integer::backward_compatibility::server_key;
use tfhe::{generate_keys, set_server_key, ClientKey, ConfigBuilder, FheUint32, ServerKey};
use tfhe::prelude::*;
use tfhe::safe_serialization::{safe_serialize, safe_deserialize};
use tfhe::conformance::ParameterSetConformant;
use tfhe::PublicKey;

/// module registration is done by the runtime, no need to explicitly do it now.
/// run $napi build
#[napi]
fn gt(clear_a: u32, clear_b: u32) -> bool {
    let config = ConfigBuilder::default().build();

    // Client-side
    let (client_key, server_key) = generate_keys(config);

    let a = FheUint32::encrypt(clear_a, &client_key);
    let b = FheUint32::encrypt(clear_b, &client_key);


    //Server-side
    set_server_key(server_key);
    //let ltresult = a.lt(b);
    let gtresult = a.gt(b);

    //Client-side
    //let decrypted_ltresult: bool = ltresult.decrypt(&client_key);
    let decrypted_gtresult: bool = gtresult.decrypt(&client_key);

    //println!("{}", decrypted_ltresult);
    //println!("{}", decrypted_gtresult);
    return decrypted_gtresult;
}

#[napi]
fn getclientkey() -> Buffer {
    let config = ConfigBuilder::default().build();

    // Client-side
    let (client_key, _) = generate_keys(config);

    let mut buffer1 = vec![];
    safe_serialize(&client_key, &mut buffer1, 1 << 30).unwrap();

    return buffer1.into();
}


#[napi]
fn getserverkey(client_key_buf:Buffer) -> Buffer {
    let client_key_buf: Vec<u8> = client_key_buf.into();
    let config = ConfigBuilder::default().build();
    let client_key_deser: ClientKey =
        safe_deserialize(client_key_buf.as_slice(), 1 << 30).unwrap();
   
    let pks = PublicKey::new(&client_key_deser);

    let mut public_key_buf = vec![];
    safe_serialize(&pks, &mut public_key_buf, 1 << 40).unwrap();

    return public_key_buf.into();
}

#[napi]
fn enc(clear_a: u32, client_key_buf:Buffer) -> u32 {
    let client_key_buf: Vec<u8> = client_key_buf.into();
    let config = ConfigBuilder::default().build();
    let client_key_deser: ClientKey =
        safe_deserialize(client_key_buf.as_slice(), 1 << 30).unwrap();
   
    let a = FheUint32::encrypt(clear_a, &client_key_deser);
    return a.decrypt(&client_key_deser);
}