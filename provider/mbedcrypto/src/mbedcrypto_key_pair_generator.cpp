//
// Created by jichan on 2019-08-21.
//

#include "mbedcrypto_key_pair_generator.hpp"

#include <mbedtls/rsa.h>
#include "mbedcrypto_key_utils.hpp"

namespace jcp {
    namespace mbedcrypto {

        class RSAKeyPairGenerator : public KeyPairGenerator {
        private:
            int key_bits_;
            jcp::SecureRandom *secure_random_;
            std::unique_ptr<jcp::SecureRandom> local_secure_random_;

        public:
            RSAKeyPairGenerator(Provider *provider) : KeyPairGenerator(provider), key_bits_(0) {}
            Result<void> initialize(int key_bits, jcp::SecureRandom *secure_random) override {
                key_bits_ = key_bits;
                if(!secure_random) {
                    local_secure_random_ = jcp::SecureRandom::getInstance(provider_);
                    if(!local_secure_random_)
                        local_secure_random_ = jcp::SecureRandom::getInstance();
                    secure_random_ = local_secure_random_.get();
                }else{
                    secure_random_ = secure_random;
                }
                return jcp::Result<void>();
            }
            Result<jcp::KeyPair> genKeyPair() override {
                int rc;

                mbedtls_rsa_context rsa;
                mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);
                rc = mbedtls_rsa_gen_key(&rsa, jcp::Random::random_cb, secure_random_, key_bits_, 0x10001);

                Result<jcp::KeyPair> result = jcp::ResultBuilder<jcp::KeyPair, void>(
                    std::move(MbedcryptoKeyUtils::makeRsaToPrivateKey(&rsa)),
                    std::move(MbedcryptoKeyUtils::makeRsaToPublicKey(&rsa))
                    ).build();

                mbedtls_rsa_free(&rsa);

                return result;
            }
        };

        class ECKeyPairGenerator : public KeyPairGenerator {
        public:
            ECKeyPairGenerator(Provider *provider) : KeyPairGenerator(provider) {}
            Result<void> initialize(int key_bits, jcp::SecureRandom *secure_random) override {
                return jcp::Result<void>();
            }
            Result<jcp::KeyPair> genKeyPair() override {
                return jcp::Result<jcp::KeyPair>();
            }
        };

        std::unique_ptr<KeyPairGenerator> MbedcryptoRSAKeyPairGeneratorFactory::create() {
            return std::make_unique<RSAKeyPairGenerator>(provider_);
        }

        std::unique_ptr<KeyPairGenerator> MbedcryptoECKeyPairGeneratorFactory::create() {
            return std::make_unique<ECKeyPairGenerator>(provider_);
        }
    }
}
