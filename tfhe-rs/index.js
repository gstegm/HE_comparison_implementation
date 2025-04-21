const addon = require("./tfhe_comparison.node");
//const clientkey = vec[0];
//const serverkey = vec[1];
//const publickey = vec[2];

const vec = addon.getKeys();
for (let i = 0; i < 10; i++) { 
    const enc_a = addon.encrypt(1743242617, vec[0]);
    const enc_b = addon.encryptPublicKey(-2200565386, vec[2]);
    const enc_comp = addon.greaterThan(enc_a, enc_b, vec[1]);
    const dec_comp = addon.decrypt(enc_comp, vec[0]);
    console.log(dec_comp);
}
//for(i=0;i<100;i++) {
//    addon.allInOne();
//}