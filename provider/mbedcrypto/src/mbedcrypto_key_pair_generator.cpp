//
// Created by jichan on 2019-08-21.
//

#include "mbedcrypto_key_pair_generator.hpp"

#include <jcp/exception/invalid_input.hpp>
#include <jcp/exception/invalid_algo_param.hpp>

#include <mbedtls/rsa.h>
#include "jcp/mbedcrypto_key_utils.hpp"

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
                return jcp::ResultBuilder<void, void>().build();
            }
            Result<void> initialize(const AlgorithmParameterSpec *algo_param_spec,
                                    jcp::SecureRandom *secure_random) override {
                return jcp::ResultBuilder<void, jcp::exception::InvalidInputException>().withException().build();
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
        private:
            mbedtls_ecp_group_id ec_grp_id_;
            jcp::SecureRandom *secure_random_;
            std::unique_ptr<jcp::SecureRandom> local_secure_random_;

            void initCommon(jcp::SecureRandom *secure_random) {
                if(!secure_random) {
                    local_secure_random_ = jcp::SecureRandom::getInstance(provider_);
                    if(!local_secure_random_)
                        local_secure_random_ = jcp::SecureRandom::getInstance();
                    secure_random_ = local_secure_random_.get();
                }else{
                    secure_random_ = secure_random;
                }
            }

        public:
            ECKeyPairGenerator(Provider *provider, mbedtls_ecp_group_id ec_grp_id) : KeyPairGenerator(provider), ec_grp_id_(ec_grp_id) {}

            Result<void> initialize(int key_bits, jcp::SecureRandom *secure_random) override {
                initCommon(secure_random);
                return jcp::ResultBuilder<void, jcp::exception::InvalidInputException>().withException().build();
            }
            Result<void> initialize(const AlgorithmParameterSpec *algo_param_spec, jcp::SecureRandom *secure_random) override {
                initCommon(secure_random);
                return jcp::ResultBuilder<void, jcp::exception::InvalidInputException>().withException().build();
            }
            Result<jcp::KeyPair> genKeyPair() override {
                mbedtls_ecp_keypair ecp;
                mbedtls_ecp_keypair_init(&ecp);
                mbedtls_ecp_gen_key(ec_grp_id_, &ecp, jcp::Random::random_cb, secure_random_);

                Result<jcp::KeyPair> result = jcp::ResultBuilder<jcp::KeyPair, void>(
                    std::move(MbedcryptoKeyUtils::makeEcpToPrivateKey(&ecp)),
                    std::move(MbedcryptoKeyUtils::makeEcpToPublicKey(&ecp))
                ).build();

                mbedtls_ecp_keypair_free(&ecp);

                return result;
            }
        };

        std::unique_ptr<KeyPairGenerator> MbedcryptoRSAKeyPairGeneratorFactory::create() {
            return std::make_unique<RSAKeyPairGenerator>(provider_);
        }

        std::unique_ptr<KeyPairGenerator> MbedcryptoECKeyPairGeneratorFactory::create() {
            return std::make_unique<ECKeyPairGenerator>(provider_, ec_grp_id_);
        }
    }
}
