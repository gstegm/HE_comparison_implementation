#include <node_api.h>
#include "binfhecontext-ser.h"
#include <bitset>

using namespace lbcrypto;

// inspirational sources:
// https://github.com/openfheorg/openfhe-development/blob/main/src/binfhe/examples/pke/boolean-pke.cpp
// https://github.com/openfheorg/openfhe-development/blob/main/src/binfhe/examples/pke/boolean-serial-json-pke.cpp
// https://www.geeksforgeeks.org/cpp-bitset-and-its-application/
// https://www.youtube.com/watch?v=CJqERG2rBaU

int greaterThan(int plainX, int plainY) {
    // Sample Program: Step 1: Set CryptoContext

    auto cc1 = BinFHEContext();

    cc1.GenerateBinFHEContext(STD128);

    // Sample Program: Step 2: Key Generation

    // Generate the secret key
    auto sk1 = cc1.KeyGen();

    std::cout << "Generating the bootstrapping keys..." << std::endl;

    // Generate the bootstrapping keys (refresh and switching keys) and public key
    cc1.BTKeyGen(sk1, PUB_ENCRYPT);
    auto pk1 = cc1.GetPublicKey();

    std::cout << "Completed the key generation." << std::endl;

    // Sample Program: Step 3: Encryption

    // Encrypt several ciphertexts representing Boolean True (1) or False (0).
    // plaintext modulus is set higher than 4 to 2 * num_of_inputs

    const int INTSIZE = 16;

    std::cout << "Encrypting first integer." << std::endl;

    std::bitset<INTSIZE> plainXBits(plainX);
    std::vector<LWECiphertext> cipherXBits;
    for (int i=0; i<INTSIZE; i++) {
        cipherXBits.push_back(cc1.Encrypt(cc1.GetPublicKey(), plainXBits[i]));
    }

    std::cout << "Encrypting second integer." << std::endl;
   
    std::bitset<INTSIZE> plainYBits(plainY);
    std::vector<LWECiphertext> cipherYBits;
    for (int i=0; i<INTSIZE; i++) {
        cipherYBits.push_back(cc1.Encrypt(cc1.GetPublicKey(), plainYBits[i]));
    }

// CODE FOR SERIALIZATION

    // Serializing key-independent crypto context
    std::string ccString = Serial::SerializeToString(cc1);
    std::cout << "The cryptocontext has been serialized." << std::endl;

    // Serializing refreshing and key switching keys (needed for bootstrapping)

    std::string refreshKeyString = Serial::SerializeToString(cc1.GetRefreshKey());
    std::cout << "The refreshing key has been serialized." << std::endl;

    std::string ksKeyString = Serial::SerializeToString(cc1.GetSwitchKey());
    std::cout << "The key switching key has been serialized." << std::endl;

    // Serializing private keys

    std::string skString = Serial::SerializeToString(sk1);
    std::cout << "The secret key sk1 key been serialized." << std::endl;

    // Serializing public keys

    std::string pkString = Serial::SerializeToString(pk1);
    std::cout << "The public key pk1 key been serialized." << std::endl;

    // Serializing a ciphertext
    std::string ctString = Serial::SerializeToString(cipherXBits[0]);
    std::cout << "length of serialized ciphertext: " << ctString.length() << std::endl;
    // if (!Serial::SerializeToFile(DATAFOLDER + "/ct1.txt", ct1, SerType::JSON)) {
    //     std::cerr << "Error serializing ct1" << std::endl;
    //     return 1;
    // }
    // std::cout << "A ciphertext has been serialized." << std::endl;

    // CODE FOR DESERIALIZATION

    // Deserializing the cryptocontext

    BinFHEContext cc;
    Serial::DeserializeFromString(cc, ccString);
    std::cout << "The cryptocontext has been deserialized." << std::endl;

    // deserializing the refreshing and switching keys (for bootstrapping)

    RingGSWACCKey refreshKey;
    Serial::DeserializeFromString(refreshKey, refreshKeyString);
    std::cout << "The refresh key has been deserialized." << std::endl;

    LWESwitchingKey ksKey;
    Serial::DeserializeFromString(ksKey, ksKeyString);
    std::cout << "The switching key has been deserialized." << std::endl;

    // Loading the keys in the cryptocontext
    cc.BTKeyLoad({refreshKey, ksKey});

    // Deserializing the secret key

    LWEPrivateKey sk;
    Serial::DeserializeFromString(sk, skString);
    std::cout << "The secret key has been deserialized." << std::endl;

    LWEPublicKey pk;
    Serial::DeserializeFromString(pk, pkString);
    std::cout << "The public key has been deserialized." << std::endl;

    // Deserializing a previously serialized ciphertext

    // LWECiphertext ct;
    // if (Serial::DeserializeFromFile(DATAFOLDER + "/ct1.txt", ct, SerType::JSON) == false) {
    //     std::cerr << "Could not deserialize the ciphertext" << std::endl;
    //     return 1;
    // }
    // std::cout << "The ciphertext has been deserialized." << std::endl;

    
    LWECiphertext z[INTSIZE][INTSIZE];
    LWECiphertext t[INTSIZE][INTSIZE];
    LWECiphertext temp;

    std::cout << "Running comparison operation." << std::endl;

    for(int j=1; j<=INTSIZE; j++) {
        int l = (j+1) / 2;
        for (int i=0; i<=INTSIZE-1; i++) {
            std::cout << "i = " << i << ", j = " << j << std::endl;
            if (j==1) {
                z[i][j-1] = cc.EvalBinGate(XNOR, cipherXBits[i], cipherYBits[i]);
                t[i][j-1] = cc.EvalBinGate(AND, cipherXBits[i], cc.EvalNOT(cipherYBits[i]));
            } else if (i+j-1 <=INTSIZE-1) {
                z[i][j-1] = cc.EvalBinGate(AND, z[i+l][j-l-1], z[i][l-1]);
                temp = cc.EvalBinGate(AND, z[i+l][j-l-1], t[i][l-1]);
                t[i][j-1] = cc.EvalBinGate(XOR, t[i+l][j-l-1], temp);
            }
        }
    }


    // Sample Program: Step 5: Decryption

    LWEPlaintext result;
    cc.Decrypt(sk, t[0][INTSIZE-1], &result);

    return (int)result;
}


napi_value GreaterThan(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value args[2];
    int64_t plainX;
    int64_t plainY;
    int64_t greaterThanResult;
    napi_value output;

    napi_get_cb_info(env, info, &argc, args, NULL, NULL);

    napi_get_value_int64(env, args[0], &plainX);
    napi_get_value_int64(env, args[1], &plainY);

    greaterThanResult = greaterThan(plainX, plainY);

    napi_create_int64(env, greaterThanResult, &output);

    return output;
}

napi_value init(napi_env env, napi_value exports) {
    napi_value greaterThan;
    napi_create_function(env, nullptr, 0, GreaterThan, nullptr, &greaterThan);
    return greaterThan;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, init);