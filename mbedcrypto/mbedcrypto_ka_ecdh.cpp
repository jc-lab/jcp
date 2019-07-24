/**
 * @file	mbedcrypto_ka_ecdh.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/22
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#include "mbedcrypto_ka_ecdh.hpp"

#include "../internal/key_accessor.hpp"
#include "../exception/general.hpp"
#include "../exception/invalid_input.hpp"
#include "../exception/invalid_key.hpp"
#include "../exception/general.hpp"

#include "../secure_random.hpp"

#include <mbedtls/ecdh.h>

#include <vector>

namespace jcp {

    namespace mbedcrypto {

        class MbedcryptoKaEcdh : public KeyAgreement {
        private:
            SecureRandom *secure_random_;
            std::unique_ptr<SecureRandom> local_secure_random_;

            mbedtls_ecdh_context ctx_priv_;
            mbedtls_ecdh_context ctx_pub_;

            std::vector<unsigned char> shared_secret_;

        public:
            MbedcryptoKaEcdh(Provider *provider) : KeyAgreement(provider), secure_random_(NULL) {
                mbedtls_ecdh_init(&ctx_priv_);
                mbedtls_ecdh_init(&ctx_pub_);
            }

            virtual ~MbedcryptoKaEcdh() {
                mbedtls_ecdh_free(&ctx_priv_);
                mbedtls_ecdh_free(&ctx_pub_);
            }

            std::unique_ptr<Result<void>> init(const AsymKey *key, SecureRandom *secure_random) override {
                if(secure_random) {
                    secure_random_ = secure_random;
                }else{
                    local_secure_random_ = SecureRandom::getInstance();
                    secure_random_ = local_secure_random_.get();
                }
				const mbedtls_ecp_keypair *keypair = key->getMbedtlsECKey();
				mbedtls_ecp_group_copy(&ctx_priv_.grp, &keypair->grp);
				mbedtls_mpi_copy(&ctx_priv_.d, &keypair->d);

                return std::unique_ptr<Result<void>>();
            }

            std::unique_ptr<Result<SecretKey>> doPhase(const AsymKey *key, SecureRandom *secure_random) override {
				int rc;
				mbedtls_mpi z;

				const mbedtls_ecp_keypair* keypair = key->getMbedtlsECKey();
				mbedtls_ecp_group_copy(&ctx_pub_.grp, &keypair->grp);
				mbedtls_ecp_copy(&ctx_pub_.Q, &keypair->Q);

				mbedtls_mpi_init(&z);
				rc = mbedtls_ecdh_compute_shared(&ctx_priv_.grp, &z,
					&ctx_pub_.Q, &ctx_priv_.d,
					Random::random_cb, secure_random_);
				if(!rc) {
                    int len = mbedtls_mpi_size(&z);
                    shared_secret_.resize(len);
                    mbedtls_mpi_write_binary(&z, &shared_secret_[0], len);
				}
				mbedtls_mpi_free(&z);
				if(rc == MBEDTLS_ERR_ECP_INVALID_KEY)
					return std::unique_ptr<Result<SecretKey>>(ResultBuilder<SecretKey, exception::InvalidKeyException>().withException().build());
				if (rc)
					return std::unique_ptr<Result<SecretKey>>(ResultBuilder<SecretKey, exception::GeneralException>().withException().build());
				return std::unique_ptr<Result<SecretKey>>(ResultBuilder<SecretKey, void>().build());
			}

            std::unique_ptr<Result<Buffer>> generateSecret() override {
				return std::unique_ptr<Result<Buffer>>(ResultBuilder<Buffer, void>(shared_secret_).build());
            }
        };

        std::unique_ptr<KeyAgreement> MbedcryptoKaEcdhFactory::create() {
            return std::unique_ptr<KeyAgreement>(new MbedcryptoKaEcdh(provider_));
        }

    } // namespace mbedcrypto

} // namespace jcp



