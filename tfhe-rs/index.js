const addon = require("./tfhe_comparison.node");
console.log(addon.gt(6, 7));
const clientkey = addon.getclientkey();
console.log(clientkey);
console.log(addon.enc(5, clientkey));