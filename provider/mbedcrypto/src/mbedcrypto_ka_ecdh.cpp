/**
 * @file	mbedcrypto_ka_ecdh.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/22
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#include "mbedcrypto_ka_ecdh.hpp"

#include <jcp/exception/general.hpp>
#include <jcp/exception/invalid_input.hpp>
#include <jcp/exception/invalid_key.hpp>
#include <jcp/exception/general.hpp>

#include "jcp/secure_random.hpp"
#include "jcp/mbedcrypto_key_utils.hpp"

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

            jcp::Result<void> init(const AsymKey *key, SecureRandom *secure_random) override {
                mbedcrypto::MbedcryptoKeyUtils key_utils(this->getProvider());

                if(secure_random) {
                    secure_random_ = secure_random;
                }else{
                    local_secure_random_ = SecureRandom::getInstance();
                    secure_random_ = local_secure_random_.get();
                }

                key_utils.setECKeyToPK(&ctx_priv_.grp, &ctx_priv_.d, NULL, dynamic_cast<const ECKey*>(key));

                return jcp::Result<void>();
            }

            jcp::Result<SecretKey> doPhase(const AsymKey *key) override {
				int rc;
				mbedtls_mpi z;

                mbedcrypto::MbedcryptoKeyUtils key_utils(this->getProvider());

                key_utils.setECKeyToPK(&ctx_pub_.grp, NULL, &ctx_pub_.Q, dynamic_cast<const ECKey*>(key));

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
					return ResultBuilder<SecretKey, exception::InvalidKeyException>().withException().build();
				if (rc)
					return jcp::Result<SecretKey>(ResultBuilder<SecretKey, exception::GeneralException>().withException().build());
				return jcp::Result<SecretKey>(ResultBuilder<SecretKey, void>().build());
			}

            jcp::Result<Buffer> generateSecret() override {
				return jcp::Result<Buffer>(ResultBuilder<Buffer, void>(shared_secret_).build());
            }
        };

        std::unique_ptr<KeyAgreement> MbedcryptoKaEcdhFactory::create() {
            return std::unique_ptr<KeyAgreement>(new MbedcryptoKaEcdh(provider_));
        }

    } // namespace mbedcrypto

} // namespace jcp



