use tfhe::{ConfigBuilder, generate_keys, set_server_key, FheUint64};
use tfhe::prelude::*;

fn main() {
    let config = ConfigBuilder::default().build();

    // Client-side
    let (client_key, server_key) = generate_keys(config);

    let clear_a = 1741357114u64;
    let clear_b = 1741357236u64;

    let a = FheUint64::encrypt(clear_a, &client_key);
    let b = FheUint64::encrypt(clear_b, &client_key);

    //Server-side
    set_server_key(server_key);
    let ltresult = a.lt(b);
    //let gtresult = a.gt(b);

    //Client-side
    let decrypted_ltresult: bool = ltresult.decrypt(&client_key);
    //let decrypted_gtresult: bool = gtresult.decrypt(&client_key);

    println!("{}", decrypted_ltresult);
    //println!("{}", decrypted_gtresult);
}
