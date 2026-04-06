//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================


#include "openfhe.h"
#include "binfhecontext.h"
#include <iostream>
#include <string>
#include <vector>

using namespace lbcrypto;
using namespace std;


void Pattern_Matching_Basic() {
    /*
  FHE-based secure pattern mathcing, no batch, basic version
 */

    cout << "\n-----Secure Pattern Matching Basic-----\n" << std::endl;

    // Step 0: input parameters for pattern matching, power of 2
    int text_size = 16;
    int pattern_size = 8;
    int alphabet_size = 26;
    int pattern_num = 4;
    cout <<"Parameters in pattern matching: text size = "<<text_size<<", pattern size = "<<pattern_size
        <<", alphabet size = "<<alphabet_size<<", number of pattern = "<<pattern_num<<endl;
    cout <<endl;

    int block_num = text_size - pattern_size + 1;
    int matrix_num = pattern_size;

    


    // Step 1: Setup CryptoContext for CKKS

    // Specify main parameters
    uint32_t multDepth    = 7; // 2 for vector*matrix (step 2.1), [log(pattern_size)] for vector*vector (step 2.2), >=2 for LUT
    uint32_t firstModSize = 60;
    uint32_t scaleModSize = 40;
    uint32_t ringDim      = 16384;
    SecurityLevel sl      = HEStd_NotSet;
    BINFHE_PARAMSET slBin = STD128; // or STD128 for real security
    uint32_t logQ_ccLWE   = 12; // uint32_t logQ_ccLWE = 25; will give modulus_LWE = 2^25 = 33,554,432 (Which is large enough for ASCII)
    // uint32_t slots        = ringDim / 2;  // Uncomment for fully-packed
    uint32_t slots     = 32;  // sparsely-packed, power of 2, >= alphabet_size
    uint32_t batchSize = slots;

    CCParams<CryptoContextCKKSRNS> parameters;

    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetFirstModSize(firstModSize);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetScalingTechnique(FLEXIBLEAUTOEXT);
    parameters.SetSecurityLevel(sl);
    parameters.SetRingDim(ringDim);
    parameters.SetBatchSize(batchSize);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    // Enable the features that you wish to use
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(SCHEMESWITCH);
    cc->Enable(ADVANCEDSHE);

    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension();
    std::cout << ", number of slots " << slots << ", and supports a multiplicative depth of " << multDepth << std::endl
              << std::endl;

    // Generate encryption keys
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    SchSwchParams params;
    params.SetSecurityLevelCKKS(sl);
    params.SetSecurityLevelFHEW(slBin);
    params.SetCtxtModSizeFHEWLargePrec(logQ_ccLWE);
    params.SetNumSlotsCKKS(slots);

    params.SetArbitraryFunctionEvaluation(true);
    params.SetNumValues(slots);

    // auto privateKeyFHEW = cc->EvalCKKStoFHEWSetup(params);
    // auto ccLWE          = cc->GetBinCCForSchemeSwitch();
    auto privateKeyFHEW = cc->EvalSchemeSwitchingSetup(params);  // Use EvalSchemeSwitchingSetup instead
    auto ccLWE          = cc->GetBinCCForSchemeSwitch();
    cc->EvalCKKStoFHEWKeyGen(keys, privateKeyFHEW);

    std::cout << "FHEW scheme is using lattice parameter " << ccLWE->GetParams()->GetLWEParams()->Getn();
    std::cout << ", logQ " << logQ_ccLWE;
    std::cout << ", and modulus q " << ccLWE->GetParams()->GetLWEParams()->Getq() << endl;

    // Compute the scaling factor to decrypt correctly in FHEW; under the hood, the LWE mod switch will performed on the ciphertext at the last level
   
    // auto modulus_LWE = 1 << logQ_ccLWE;  // 2^25 = 33,554,432
    // auto beta        = ccLWE->GetBeta().ConvertToInt();
    auto pLWE1       = ccLWE->GetMaxPlaintextSpace().ConvertToInt();  // Small precision
    // auto pLWE1       = modulus_LWE / (2 * beta);  // This will be large enough for ASCII
    double scale1 = 1.0 / pLWE1;
    
    std::cout << "Plaintext modulus (pLWE1) = " << pLWE1 << std::endl << std::endl;  

    // Perform the precomputation for switching
    cc->EvalCKKStoFHEWPrecompute(scale1);

    cout << "Generating the LUT keys..." << endl;
    ccLWE->BTKeyGen(privateKeyFHEW);
    cout << "Completed the key generation." << endl;

    // Step 3: Encoding and encryption of inputs

    vector<vector<vector<double>>> M(matrix_num, vector<vector<double>>(slots,vector<double>(pattern_num,0)));
    for (int i = 0; i < matrix_num; ++i){
        for (int j = 0 ; j < pattern_num ; ++j){
            int index = (29+i+j)%alphabet_size;
            M[i][index][j] = 1;
        }
    }

    cout <<"Sample matrix generated. number of matrices = "<<matrix_num<<", size of matrix = "
    << alphabet_size <<" * "<<pattern_num<<endl;

    vector<vector<double>> input(text_size,vector<double>(alphabet_size,0));
    for (int i = 0; i < text_size; ++i){
        int index = (10+i)%alphabet_size;
        input[i][index] = 1;
    }

    cout <<"Sample input generated. "<<endl<<endl;;
    

    // Inputs -> ciphertext
    //uint32_t encodedLength1 = input[0].size();
    vector<ReadOnlyCiphertext<DCRTPoly>> ct;
    
    for (int i = 0 ; i < text_size ; ++i){
        // Encoding as plaintexts
        Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(input[i], 1, 0, nullptr);
        // Encrypt the encoded vectors
        auto c = cc->Encrypt(keys.publicKey, ptxt1);
        ct.push_back(c);
    }

    cout <<"number of modulus in modulus chain = "<<ct[0]->GetElements()[0].GetNumOfElements()<<endl;

    //Step 4: Pattern matching evaluation
    vector<Ciphertext<DCRTPoly>> output_block(block_num);
    cout <<"number of tracks = "<<block_num<<endl;

    // for each track
    for(int i = 0 ; i < block_num ; ++i){
        //compute enc(v)*M
        vector<Ciphertext<DCRTPoly>> output_LT(pattern_size);
        for (int j = 0 ; j < pattern_size ; ++j){
            for (int k = 0 ; k < pattern_num ; ++k){
                vector<double> tmp_vec(slots,0);
                for (int k2 = 0 ; k2 < (int)slots; ++k2){
                    tmp_vec[k2] = M[j][k2][k];
                }
                // inner product between enc(v)*tmp_vec
                Plaintext tmp_pt = cc->MakeCKKSPackedPlaintext(tmp_vec);
                auto ip_result     = cc->EvalInnerProduct(ct[i+j], tmp_pt, batchSize);
                //mask
                vector<double> mask(slots,0);
                mask[k] = 1;
                Plaintext mask_pt = cc->MakeCKKSPackedPlaintext(tmp_vec);
                auto ip_masked = cc->EvalMult(ip_result, mask_pt);

                if(k == 0){
                    output_LT[j] = ip_masked;
                }
                else{
                    output_LT[j] = cc->EvalAdd(output_LT[j], ip_masked);
                }

            }
        }
        cout <<"track id: "<<i <<", Enc(vec)*M finished. "<<endl;
        //cout <<"number of modulus in modulus chain = "<<output_LT[0]->GetElements()[0].GetNumOfElements()<<endl;

        //compute enc(v)*enc(v)*...*enc(v)
        int index = 2;
        while(index <= pattern_size){
            for(int i = 0; i < pattern_size ; i += index){
                if(i + index/2 < pattern_size){
                    auto ct_tmp = cc->EvalMult(output_LT[i], output_LT[i+index/2]);
                    //cout <<i <<" * "<<i+index/2<<endl;
                    output_LT[i] = ct_tmp;
                }
                else;
            }
            index *= 2;
        }
        cout <<"position-wise multiplication in each track finished. "<<endl;
        //cout <<"number of modulus in modulus chain = "<<output_LT[0]->GetElements()[0].GetNumOfElements()<<endl;

        //output of each track
        output_block[i] = output_LT[0];
    }
    cout <<endl;

    //sum up output of each track
    auto ct_sum = output_block[0];
    for (int i = 1; i < block_num; ++i){
        ct_sum = cc->EvalAdd(ct_sum, output_block[i]);
    }

    cout <<"position-wise addition among output from each track finished. "<<endl;

    //sum up all elements in ct_sum
    auto ct_sum2 = cc -> EvalSum(ct_sum,batchSize);

    cout <<"Sum elements in output ct finished. "<<endl;

    //extract to FHEW ciphertext
    auto cTemp = cc->EvalCKKStoFHEW(ct_sum2, 1);
    cout <<"extracted to FHEW ct finished, number of FHEW ct = "<<cTemp.size()<<endl;

    

    auto fp = [](NativeInteger m, NativeInteger p1) -> NativeInteger {
        if (m >= 1)
            return 1;
        else
            return 0;
    };

    auto lut = ccLWE->GenerateLUTviaFunction(fp, pLWE1);

    auto ct_result = ccLWE->EvalFunc(cTemp[0], lut);

    cout <<"LUT finished. "<<endl;






    

}

int main() {
    Pattern_Matching_Basic();
    return 0;
}