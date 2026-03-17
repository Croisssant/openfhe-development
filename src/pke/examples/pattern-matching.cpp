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
    uint32_t logQ_ccLWE   = 12; // uint32_t logQ_ccLWE = 25; will give modulus_LWE = 2^25 = 33,554,432 (Which is large enough for ASCII)
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

    params.SetArbitraryFunctionEvaluation(true);
    params.SetNumValues(slots);

    // auto privateKeyFHEW = cc->EvalCKKStoFHEWSetup(params);
    // auto ccLWE          = cc->GetBinCCForSchemeSwitch();
    auto privateKeyFHEW = cc->EvalSchemeSwitchingSetup(params);  // Use EvalSchemeSwitchingSetup instead
    auto ccLWE          = cc->GetBinCCForSchemeSwitch();
    cc->EvalCKKStoFHEWKeyGen(keys, privateKeyFHEW);

    std::cout << "FHEW scheme is using lattice parameter " << ccLWE->GetParams()->GetLWEParams()->Getn();
    std::cout << ", logQ " << logQ_ccLWE;
    std::cout << ", and modulus q " << ccLWE->GetParams()->GetLWEParams()->Getq() << std::endl << std::endl;

    // Compute the scaling factor to decrypt correctly in FHEW; under the hood, the LWE mod switch will performed on the ciphertext at the last level
   
    // auto modulus_LWE = 1 << logQ_ccLWE;  // 2^25 = 33,554,432
    // auto beta        = ccLWE->GetBeta().ConvertToInt();
    auto pLWE1       = ccLWE->GetMaxPlaintextSpace().ConvertToInt();  // Small precision
    // auto pLWE1       = modulus_LWE / (2 * beta);  // This will be large enough for ASCII
    double scale1 = 1.0 / pLWE1;
    
    std::cout << "Plaintext modulus (pLWE1) = " << pLWE1 << std::endl << std::endl;  

    // Perform the precomputation for switching
    cc->EvalCKKStoFHEWPrecompute(scale1);

    // Step 3: Encoding and encryption of inputs

    // Inputs
    std::vector<double> x1  = { 0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 15.0, 16.0, 17.0 };
    uint32_t encodedLength1 = x1.size();
 
    // Encoding as plaintexts
    Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1, 1, 0, nullptr);

    // Encrypt the encoded vectors
    auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
   
    // Multiplication on CKKS ciphertext (c1)
    // Generate multiplication keys for CKKS operations
    cc->EvalMultKeyGen(keys.secretKey);
    auto c1_scaled = cc->EvalMult(c1, 2.0);

    // Transform the ciphertext from CKKS to FHEW
    auto cTemp = cc->EvalCKKStoFHEW(c1_scaled, encodedLength1);


    // LUT Section
    std::cout << "Generating the bootstrapping keys..." << std::endl;
    ccLWE->BTKeyGen(privateKeyFHEW);
    std::cout << "Completed the key generation." << std::endl;

    auto fp = [](NativeInteger m, NativeInteger p1) -> NativeInteger {
        if (m >= 4)
            return 1;
        else
            return 0;
    };

    auto lut = ccLWE->GenerateLUTviaFunction(fp, pLWE1);
    std::cout << "\n---Applying LUT to switched ciphertexts---\n" << std::endl;
    std::vector<LWECiphertext> cResults;
    for (uint32_t i = 0; i < cTemp.size(); ++i) {
        auto ct_result = ccLWE->EvalFunc(cTemp[i], lut);
        cResults.push_back(ct_result);
    }


    std::cout << "FHEW decryption & LUT results: ";
    LWEPlaintext lutResult;
    for (uint32_t i = 0; i < cTemp.size(); ++i) {
        ccLWE->Decrypt(privateKeyFHEW, cResults[i], &lutResult, pLWE1);
        std::cout << lutResult << " ";
    }

    std::cout << std::endl;

}

int main() {
    SwitchCKKSToFHEW();
    return 0;
}