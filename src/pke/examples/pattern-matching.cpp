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

/*
  Examples for scheme switching between CKKS and FHEW and back, with intermediate computations
 */

#include "openfhe.h"
#include "binfhecontext.h"
#include <iostream>
#include <string>

using namespace lbcrypto;


void SwitchCKKSToFHEW();
void FHEWLut();


int main() {
    SwitchCKKSToFHEW();
    FHEWLut();

    return 0;
}


void SwitchCKKSToFHEW() {
    /*
  Example of switching a packed ciphertext from CKKS to multiple FHEW ciphertexts.
 */

    std::cout << "\n-----SwitchCKKSToFHEW-----\n" << std::endl;

    // Step 1: Setup CryptoContext for CKKS

    // Specify main parameters
    uint32_t multDepth    = 3;
    uint32_t firstModSize = 60;
    uint32_t scaleModSize = 50;
    uint32_t ringDim      = 4096;
    SecurityLevel sl      = HEStd_NotSet;
    BINFHE_PARAMSET slBin = STD128; // or STD128 for real security
    uint32_t logQ_ccLWE   = 25; // This gives modulus_LWE = 2^25 = 33,554,432
    // uint32_t slots        = ringDim / 2;  // Uncomment for fully-packed
    uint32_t slots     = 16;  // sparsely-packed
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

    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension();
    std::cout << ", number of slots " << slots << ", and supports a multiplicative depth of " << multDepth << std::endl
              << std::endl;

    // Generate encryption keys
    auto keys = cc->KeyGen();

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    SchSwchParams params;
    params.SetSecurityLevelCKKS(sl);
    params.SetSecurityLevelFHEW(slBin);
    params.SetCtxtModSizeFHEWLargePrec(logQ_ccLWE);
    params.SetNumSlotsCKKS(slots);
    auto privateKeyFHEW = cc->EvalCKKStoFHEWSetup(params);
    auto ccLWE          = cc->GetBinCCForSchemeSwitch();
    cc->EvalCKKStoFHEWKeyGen(keys, privateKeyFHEW);

    std::cout << "FHEW scheme is using lattice parameter " << ccLWE->GetParams()->GetLWEParams()->Getn();
    std::cout << ", logQ " << logQ_ccLWE;
    std::cout << ", and modulus q " << ccLWE->GetParams()->GetLWEParams()->Getq() << std::endl << std::endl;

    // Compute the scaling factor to decrypt correctly in FHEW; under the hood, the LWE mod switch will performed on the ciphertext at the last level
   
    auto modulus_LWE = 1 << logQ_ccLWE;  // 2^25 = 33,554,432
    auto beta        = ccLWE->GetBeta().ConvertToInt();
    // auto pLWE1       = ccLWE->GetMaxPlaintextSpace().ConvertToInt();  // Small precision
    auto pLWE1       = modulus_LWE / (2 * beta);  // This will be large enough for ASCII
    double scale1 = 1.0 / pLWE1;
  
    // Perform the precomputation for switching
    cc->EvalCKKStoFHEWPrecompute(scale1);

    // Step 3: Encoding and encryption of inputs

    // Inputs

    std::string sentence {};
    std::cout << "Please enter your sentence\n>> ";
    getline(std::cin, sentence);

    std::cout << "\nYou entered: \n" << sentence << std::endl;

    std::vector<double> x1(sentence.begin(), sentence.end());
    
    uint32_t encodedLength1 = x1.size();
 

    // Encoding as plaintexts
    Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1, 1, 0, nullptr);

    // Encrypt the encoded vectors
    auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
   
    // Step 2
    // Plaintext ptxt2 = do some multiplication on c1

    // Step 4: Scheme switching from CKKS to FHEW

    // A: First scheme switching case

    // Transform the ciphertext from CKKS to FHEW
    auto cTemp = cc->EvalCKKStoFHEW(c1, encodedLength1);

    std::cout << "\n---Decrypting switched ciphertext with large precision (plaintext modulus " 
              << NativeInteger(pLWE1)
              << ")---\n"
              << std::endl;

    std::vector<int32_t> x1Int(encodedLength1);
    std::transform(x1.begin(), x1.end(), x1Int.begin(), [&](const double& elem) {
        return static_cast<int32_t>(static_cast<int32_t>(std::round(elem)) % pLWE1);
    });
    ptxt1->SetLength(encodedLength1);
    std::cout << "Input x1: " << ptxt1->GetRealPackedValue() << "; which rounds to: " << x1Int << std::endl;

    std::cout << "\n" << std::endl;

    std::cout << "FHEW decryption (int): ";
    LWEPlaintext result;
    for (uint32_t i = 0; i < cTemp.size(); ++i) {
        ccLWE->Decrypt(privateKeyFHEW, cTemp[i], &result, pLWE1);
        std::cout << result << " ";
    }
    
    std::cout << "\n";
    
    std::cout << "FHEW decryption (char): ";
    for (uint32_t i = 0; i < cTemp.size(); ++i) {
        ccLWE->Decrypt(privateKeyFHEW, cTemp[i], &result, pLWE1);
        std::cout << (char)result;
    }
    std::cout << "\n" << std::endl;


}

void FHEWLut() {
    // Sample Program: Step 1: Set CryptoContext
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(STD128, true, 12);

    // Sample Program: Step 2: Key Generation

    // Generate the secret key
    auto sk = cc.KeyGen();

    std::cout << "Generating the bootstrapping keys..." << std::endl;

    // Generate the bootstrapping keys (refresh and switching keys)
    cc.BTKeyGen(sk);

    std::cout << "Completed the key generation." << std::endl;

    // Sample Program: Step 3: Create the to-be-evaluated funciton and obtain its corresponding LUT
    int p = cc.GetMaxPlaintextSpace().ConvertToInt();  // Obtain the maximum plaintext space

    // Initialize Function f(x) = x^3 % p
    auto fp = [](NativeInteger m, NativeInteger p1) -> NativeInteger {
        if (m < p1)
            return (m * m * m) % p1;
        else
            return ((m - p1 / 2) * (m - p1 / 2) * (m - p1 / 2)) % p1;



        // Step 1
        // Join scheme-swtiching and eval-function and use the following conditions for fp
        // if(m >= p1) {
        //     return 1
        // } else {
        //     return 0
        // }

        //  Sample input: 0 to 7
    };

    // Generate LUT from function f(x)
    auto lut = cc.GenerateLUTviaFunction(fp, p);
    std::cout << "Evaluate x^3%" << p << "." << std::endl;

    // Sample Program: Step 4: evalute f(x) homomorphically and decrypt
    // Note that we check for all the possible plaintexts.
    for (int i = 0; i < p; i++) {
        auto ct1 = cc.Encrypt(sk, i % p, LARGE_DIM, p);

        auto ct_cube = cc.EvalFunc(ct1, lut);

        LWEPlaintext result;

        cc.Decrypt(sk, ct_cube, &result, p);

        std::cout << "Input: " << i << ". Expected: " << fp(i, p) << ". Evaluated = " << result << std::endl;
    }

}
