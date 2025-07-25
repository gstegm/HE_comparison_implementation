# Comparison Operations for Homomorphic Encryption
For both variants, make sure to have Node.js/npm installed on your system, as described [here](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm).
## Using TFHE-rs with NAPI-RS
To use this project, Rust needs to be installed on your system, which is described [here](https://www.rust-lang.org/tools/install).

Make sure that all dependencies are installed or install them by running the following command in the `TFHE-rs_NAPI-RS` folder:
```shell
npm install
```
To build the TFHE-rs addon, the following commadn has to be executed:
```shell
npm run build
```

Then, a small testing environment can be executed with the following command after changing the working directory to the folder `TFHE-rs_NAPI-RS`:
```shell
node index.js
```

## Using OpenFHE with Node-API

To use this project, OpenFHE needs to be installed, which is described [here](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/installation/installation.html). Importantly, don't forget to install OpenFHE to a system directory at the end of the process. The installation was tested for Ubuntu 24.04 LTS as well as Ubuntu 24.10.

To install all necessary dependencies, run
```shell
npm install
```
in the folder `OpenFHE_Node-API`.

A small performance measurement environment can be executed with the following command:
```shell
node index.js
```

 # References 
- [TFHE-rs](https://github.com/zama-ai/tfhe-rs) library for homomorphic encryption in Rust, based on the TFHE encryption scheme. Read the documentation [here](https://docs.zama.ai/tfhe-rs).
- [NAPI-RS](https://github.com/napi-rs/napi-rs) library for building compiled Node.js addons in Rust. Read the documentation [here](https://napi.rs/docs/introduction/getting-started).
- [OpenFHE](https://github.com/openfheorg/openfhe-development) library for homomorphic encryption in C++. Read the documentation [here](https://openfhe-development.readthedocs.io/en/latest/)
- Node-API library for building native addons for Node.js. Read the documentation [here](https://nodejs.org/api/n-api.html).