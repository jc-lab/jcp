/**
 * @file	openssl_ka_ecdh.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/08/14
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#include "openssl_ka_ecdh.hpp"

#include "../internal/key_accessor.hpp"
#include "../exception/general.hpp"
#include "../exception/invalid_input.hpp"
#include "../exception/invalid_key.hpp"
#include "../exception/general.hpp"

#include "../secure_random.hpp"

#include <openssl/ecdh.h>

#include <vector>

namespace jcp {

    namespace openssl {

        class OpensslKaEcdh : public KeyAgreement {
        private:
            SecureRandom *secure_random_;
            std::unique_ptr<SecureRandom> local_secure_random_;

			std::unique_ptr<EC_KEY, void(*)(EC_KEY*)> key_pri_;

            std::vector<unsigned char> shared_secret_;

        public:
            OpensslKaEcdh(Provider *provider) : KeyAgreement(provider), secure_random_(NULL),
				key_pri_(NULL, EC_KEY_free) {
            }

            virtual ~OpensslKaEcdh() {
            }

            std::unique_ptr<Result<void>> init(const AsymKey *key, SecureRandom *secure_random) override {
                if(secure_random) {
                    secure_random_ = secure_random;
                }else{
                    local_secure_random_ = SecureRandom::getInstance();
                    secure_random_ = local_secure_random_.get();
                }
				key_pri_.reset(EC_KEY_dup(key->getOpensslECKey()));
                return std::unique_ptr<Result<void>>();
            }

            std::unique_ptr<Result<SecretKey>> doPhase(const AsymKey *key, SecureRandom *secure_random) override {
				int rc;

				EC_KEY* eckey = (EC_KEY*)key->getOpensslECKey();

				int secret_len;
				int field_size;
				unsigned char* secret;

				/* Calculate the size of the buffer for the shared secret */
				field_size = EC_GROUP_get_degree(EC_KEY_get0_group(key_pri_.get()));
				secret_len = (field_size + 7) / 8;

				shared_secret_.resize(secret_len);

				/* Derive the shared secret */
				secret_len = ECDH_compute_key(0, 0, EC_KEY_get0_public_key(eckey), key_pri_.get(), NULL);

				if (secret_len <= 0) {
					return std::unique_ptr<Result<SecretKey>>(ResultBuilder<SecretKey, exception::InvalidKeyException>().withException().build());
				}

				if (shared_secret_.size() != secret_len)
					shared_secret_.resize(secret_len);

				return std::unique_ptr<Result<SecretKey>>(ResultBuilder<SecretKey, void>().build());
			}

            std::unique_ptr<Result<Buffer>> generateSecret() override {
				return std::unique_ptr<Result<Buffer>>(ResultBuilder<Buffer, void>(shared_secret_).build());
            }
        };

        std::unique_ptr<KeyAgreement> OpensslKaEcdhFactory::create() {
            return std::unique_ptr<KeyAgreement>(new OpensslKaEcdh(provider_));
        }

    } // namespace openssl

} // namespace jcp



