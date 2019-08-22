/**
 * @file	mbedcrypto_cipher_asym.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/22
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#include "mbedcrypto_cipher_asym.hpp"

#include <jcp/exception/general.hpp>
#include <jcp/exception/invalid_input.hpp>
#include <jcp/exception/invalid_key.hpp>

#include "jcp/secure_random.hpp"

#include "mbedcrypto_key_utils.hpp"

#include <mbedtls/md.h>
#include <mbedtls/pk.h>

#include <vector>

namespace jcp {

    namespace mbedcrypto {

        class MbedcryptoAsymCipher : public Cipher {
        private:
            mbedtls_pk_type_t pk_type_;
			int padding_type_;

            mbedtls_pk_context pk_;
            bool encrypt_mode_;

            std::vector<unsigned char> input_buf_;

            std::unique_ptr<SecureRandom> local_secure_random_;
            SecureRandom *secure_random_;

        public:
            MbedcryptoAsymCipher(Provider *provider, mbedtls_pk_type_t pk_type, int padding_type) : Cipher(provider), pk_type_(pk_type), padding_type_(padding_type), secure_random_(NULL) {
                memset(&pk_, 0, sizeof(pk_));
            }

            jcp::Result<void> init(int mode, const SecretKey *key, const AlgorithmParameterSpec *algorithmParameterSpec, SecureRandom *secure_random) override {
                return ResultBuilder<void, exception::InvalidKeyException>().withException().build();
            }

            jcp::Result<void> init(int mode, const AsymKey *key, const AlgorithmParameterSpec *algorithmParameterSpec, SecureRandom *secure_random) override {
				int rc;
				mbedcrypto::MbedcryptoKeyUtils key_utils(this->getProvider());

                const mbedtls_pk_info_t *pk_info = mbedtls_pk_info_from_type(pk_type_);
				switch(mode) {
                    case ENCRYPT_MODE:
                        encrypt_mode_ = true;
                        break;
                    case DECRYPT_MODE:
                        encrypt_mode_ = false;
                        break;
                }
                if(secure_random) {
                    secure_random_ = secure_random;
                }else{
                    local_secure_random_ = SecureRandom::getInstance();
                    secure_random_ = local_secure_random_.get();
                }
                rc = mbedtls_pk_setup(&pk_, pk_info);
				if (rc)
				{
					return jcp::Result<void>(ResultBuilder<void, exception::GeneralException>().withException().build());
				}

				switch(pk_type_) {
                    case MBEDTLS_PK_RSA:
				    case MBEDTLS_PK_RSA_ALT:
                    case MBEDTLS_PK_RSASSA_PSS:
                        key_utils.setRSAKeyToPK(mbedtls_pk_rsa(pk_), dynamic_cast<const RSAKey*>(key));
                        break;
                    case MBEDTLS_PK_ECKEY:
                    case MBEDTLS_PK_ECKEY_DH:
                    case MBEDTLS_PK_ECDSA:
                        key_utils.setECKeyToPK(mbedtls_pk_ec(pk_), dynamic_cast<const ECKey*>(key));
                        break;
				}
				return ResultBuilder<void, void>().build();
            }

            int getBlockSize() override {
                return 0;
            }

            jcp::Result<void> updateAAD(const void *auth, size_t length) override {
                return jcp::Result<void>(ResultBuilder<void, exception::InvalidInputException>().withException().build());
            }

            jcp::Result<Buffer> update(const void *buf, size_t length) override {
                const unsigned char *pin = (const unsigned char*)buf;
                input_buf_.insert(input_buf_.end(), &pin[0], &pin[length]);
                return jcp::Result<Buffer>(ResultBuilder<Buffer, void>().build());
            }

            jcp::Result<Buffer> doFinal() override {
                int rc;
                std::vector<unsigned char> outbuf(65536);
                size_t olen = 0;
                if(encrypt_mode_) {
                    rc = mbedtls_pk_encrypt(&pk_, input_buf_.data(), input_buf_.size(), &outbuf[0], &olen, outbuf.size(), Random::random_cb, secure_random_);
                }else{
                    rc = mbedtls_pk_decrypt(&pk_, input_buf_.data(), input_buf_.size(), &outbuf[0], &olen, outbuf.size(), Random::random_cb, secure_random_);
                }
                if(rc) {
                    return jcp::Result<Buffer>(ResultBuilder<Buffer, exception::InvalidInputException>().withException("pk failed", rc).build());
                }
				outbuf.resize(olen);
                return jcp::Result<Buffer>(ResultBuilder<Buffer, void>(outbuf).build());
            }

            std::unique_ptr<Buffer> getIv() override {
				return NULL;
            }
        };

        std::unique_ptr<Cipher> MbedcryptoAsymCipherFactory::create() {
			return std::unique_ptr<Cipher>(new MbedcryptoAsymCipher(provider_, pk_type_, padding_type_));
        }

    } // namespace mbedcrypto

} // namespace jcp



