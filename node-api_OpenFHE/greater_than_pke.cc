#include <node_api.h>
#include "binfhecontext-ser.h"
#include <bitset>

using namespace lbcrypto;

// inspirational sources:
// https://github.com/openfheorg/openfhe-development/blob/main/src/binfhe/examples/pke/boolean-pke.cpp
// https://github.com/openfheorg/openfhe-development/blob/main/src/binfhe/examples/pke/boolean-serial-json-pke.cpp
// https://www.geeksforgeeks.org/cpp-bitset-and-its-application/
// https://www.youtube.com/watch?v=CJqERG2rBaU

int compare(int first, int second) {
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

    const int INTSIZE = 64;

    std::cout << "Encrypting first integer." << std::endl;

    std::bitset<INTSIZE> bitseq1(first);
    std::vector<LWECiphertext> ctvec1;
    for (int i=0; i<INTSIZE; i++) {
        ctvec1.push_back(cc1.Encrypt(cc1.GetPublicKey(), bitseq1[i]));
    }

    std::cout << "Encrypting second integer." << std::endl;
   
    std::bitset<INTSIZE> bitseq2(second);
    std::vector<LWECiphertext> ctvec2;
    for (int i=0; i<INTSIZE; i++) {
        ctvec2.push_back(cc1.Encrypt(cc1.GetPublicKey(), bitseq2[i]));
    }

// CODE FOR SERIALIZATION

    const std::string DATAFOLDER = "demoData";

    // Serializing key-independent crypto context

    if (!Serial::SerializeToFile(DATAFOLDER + "/cryptoContext.txt", cc1, SerType::JSON)) {
        std::cerr << "Error serializing the cryptocontext" << std::endl;
        return 1;
    }
    std::cout << "The cryptocontext has been serialized." << std::endl;

    // Serializing refreshing and key switching keys (needed for bootstrapping)

    if (!Serial::SerializeToFile(DATAFOLDER + "/refreshKey.txt", cc1.GetRefreshKey(), SerType::JSON)) {
        std::cerr << "Error serializing the refreshing key" << std::endl;
        return 1;
    }
    std::cout << "The refreshing key has been serialized." << std::endl;

    if (!Serial::SerializeToFile(DATAFOLDER + "/ksKey.txt", cc1.GetSwitchKey(), SerType::JSON)) {
        std::cerr << "Error serializing the switching key" << std::endl;
        return 1;
    }
    std::cout << "The key switching key has been serialized." << std::endl;

    // Serializing private keys

    if (!Serial::SerializeToFile(DATAFOLDER + "/sk1.txt", sk1, SerType::JSON)) {
        std::cerr << "Error serializing sk1" << std::endl;
        return 1;
    }
    std::cout << "The secret key sk1 key been serialized." << std::endl;

    // Serializing public keys

    if (!Serial::SerializeToFile(DATAFOLDER + "/pk1.txt", pk1, SerType::JSON)) {
        std::cerr << "Error serializing pk1" << std::endl;
        return 1;
    }
    std::cout << "The public key pk1 key been serialized." << std::endl;

    // Serializing a ciphertext

    // if (!Serial::SerializeToFile(DATAFOLDER + "/ct1.txt", ct1, SerType::JSON)) {
    //     std::cerr << "Error serializing ct1" << std::endl;
    //     return 1;
    // }
    // std::cout << "A ciphertext has been serialized." << std::endl;

    // CODE FOR DESERIALIZATION

    // Deserializing the cryptocontext

    BinFHEContext cc;
    if (Serial::DeserializeFromFile(DATAFOLDER + "/cryptoContext.txt", cc, SerType::JSON) == false) {
        std::cerr << "Could not deserialize the cryptocontext" << std::endl;
        return 1;
    }
    std::cout << "The cryptocontext has been deserialized." << std::endl;

    // deserializing the refreshing and switching keys (for bootstrapping)

    RingGSWACCKey refreshKey;
    if (Serial::DeserializeFromFile(DATAFOLDER + "/refreshKey.txt", refreshKey, SerType::JSON) == false) {
        std::cerr << "Could not deserialize the refresh key" << std::endl;
        return 1;
    }
    std::cout << "The refresh key has been deserialized." << std::endl;

    LWESwitchingKey ksKey;
    if (Serial::DeserializeFromFile(DATAFOLDER + "/ksKey.txt", ksKey, SerType::JSON) == false) {
        std::cerr << "Could not deserialize the switching key" << std::endl;
        return 1;
    }
    std::cout << "The switching key has been deserialized." << std::endl;

    // Loading the keys in the cryptocontext
    cc.BTKeyLoad({refreshKey, ksKey});

    // Deserializing the secret key

    LWEPrivateKey sk;
    if (Serial::DeserializeFromFile(DATAFOLDER + "/sk1.txt", sk, SerType::JSON) == false) {
        std::cerr << "Could not deserialize the secret key" << std::endl;
        return 1;
    }
    std::cout << "The secret key has been deserialized." << std::endl;

    LWEPublicKey pk;
    if (Serial::DeserializeFromFile(DATAFOLDER + "/pk1.txt", pk, SerType::JSON) == false) {
        std::cerr << "Could not deserialize the public key" << std::endl;
        return 1;
    }
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
                z[i][j-1] = cc.EvalBinGate(XNOR, ctvec1[i], ctvec2[i]);
                t[i][j-1] = cc.EvalBinGate(AND, ctvec1[i], cc.EvalNOT(ctvec2[i]));
                
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
    int64_t first;
    int64_t second;
    int64_t greater_than_result;
    napi_value output;

    napi_get_cb_info(env, info, &argc, args, NULL, NULL);

    napi_get_value_int64(env, args[0], &first);
    napi_get_value_int64(env, args[1], &second);

    greater_than_result = compare(first, second);

    napi_create_int64(env, greater_than_result, &output);

    return output;
}

napi_value init(napi_env env, napi_value exports) {
    napi_value greater_than;
    napi_create_function(env, nullptr, 0, GreaterThan, nullptr, &greater_than);
    return greater_than;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, init);