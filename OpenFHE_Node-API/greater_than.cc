#include <node_api.h>
#include "binfhecontext.h"
#include <bitset>

using namespace lbcrypto;

//void encryptBits(std::vector<bool> bitvector, std::vector<LWECiphertext> ctvec, BinFHEContext cc, LWEPrivateKey sk) {
//        for (int i=0; i<(int)bitvector.size(); i++) {
//            ctvec.push_back(cc.Encrypt(sk, bitvector[i]));
//        }
//    }

int compare(int first, int second) {
    // Sample Program: Step 1: Set CryptoContext

    auto cc = BinFHEContext();

    cc.GenerateBinFHEContext(STD128, GINX);

    // Sample Program: Step 2: Key Generation

    // Generate the secret key
    auto sk = cc.KeyGen();

    std::cout << "Generating the bootstrapping keys..." << std::endl;

    // Generate the bootstrapping keys (refresh and switching keys)
    cc.BTKeyGen(sk);

    std::cout << "Completed the key generation." << std::endl;

    // Sample Program: Step 3: Encryption

    // Encrypt several ciphertexts representing Boolean True (1) or False (0).
    // plaintext modulus is set higher than 4 to 2 * num_of_inputs

    const int INTSIZE = 64;

    std::cout << "Encrypting first integer." << std::endl;

    std::bitset<INTSIZE> bitseq1(first);
    std::vector<LWECiphertext> ctvec1;
    for (int i=0; i<INTSIZE; i++) {
        ctvec1.push_back(cc.Encrypt(sk, bitseq1[i]));
    }

    std::cout << "Encrypting second integer." << std::endl;
   
    std::bitset<INTSIZE> bitseq2(second);
    std::vector<LWECiphertext> ctvec2;
    for (int i=0; i<INTSIZE; i++) {
        ctvec2.push_back(cc.Encrypt(sk, bitseq2[i]));
    }
    
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