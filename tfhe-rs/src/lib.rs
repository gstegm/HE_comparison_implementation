/// import the preludes
use napi::bindgen_prelude::*;
use napi_derive::napi;
use tfhe::{ConfigBuilder, generate_keys, set_server_key, FheUint32};
use tfhe::prelude::*;

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
    let ltresult = a.lt(b);
    //let gtresult = a.gt(b);

    //Client-side
    let decrypted_ltresult: bool = ltresult.decrypt(&client_key);
    //let decrypted_gtresult: bool = gtresult.decrypt(&client_key);

    //println!("{}", decrypted_ltresult);
    //println!("{}", decrypted_gtresult);
    return decrypted_ltresult;
}