/**
 * @file	mbedcrypto_sign.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/22
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#include <mbedtls/ecp.h>
#include <mbedtls/pk.h>
#include "mbedcrypto_sign.hpp"
#include "mbedcrypto_md.hpp"

#include "../secure_random.hpp"
#include "../exception/general.hpp"

#include "../message_digest.hpp"

namespace jcp {

    namespace mbedcrypto {

        class MbedcryptoSign : public Signature {
        private:
            mbedtls_pk_type_t pk_type_;
			mbedtls_md_type_t md_type_;
			MbedcryptoMessageDigestFactory* md_factory_;

            mbedtls_pk_context pk_;
            bool verify_mode_;

			std::unique_ptr<MessageDigest> message_digest_;

            std::vector<unsigned char> input_buf_;

            std::unique_ptr<SecureRandom> local_secure_random_;
            SecureRandom *secure_random_;

        public:
            MbedcryptoSign(Provider *provider, mbedtls_pk_type_t pk_type, mbedtls_md_type_t md_type, MbedcryptoMessageDigestFactory* md_factory)
                : Signature(provider), pk_type_(pk_type), md_type_(md_type), md_factory_(md_factory)
            {
            }

            std::unique_ptr<Result<void>> initCommon(const AsymKey *key, SecureRandom *secure_random) {
                int rc;
                const mbedtls_pk_info_t *pk_info = mbedtls_pk_info_from_type(pk_type_);
                rc = mbedtls_pk_setup(&pk_, pk_info);
                if (rc)
                {
                    return std::unique_ptr<Result<void>>(ResultBuilder<void, exception::GeneralException>().withException().build());
                }
                if (key->isRSAKey())
                {
                    mbedtls_rsa_copy(mbedtls_pk_rsa(pk_), key->getMbedtlsRSAKey());
                }
                else if (key->isECKey())
                {
                    const mbedtls_ecp_keypair* src = key->getMbedtlsECKey();
                    mbedtls_ecp_keypair* dst = mbedtls_pk_ec(pk_);
                    mbedtls_ecp_group_copy(&dst->grp, &src->grp);
                    if(verify_mode_)
                        mbedtls_ecp_copy(&dst->Q, &src->Q);
                    else
                        mbedtls_mpi_copy(&dst->d, &src->d);
                }
                if(!verify_mode_) {
                    if (secure_random) {
                        secure_random_ = secure_random;
                    } else {
                        local_secure_random_ = SecureRandom::getInstance();
                        secure_random_ = local_secure_random_.get();
                    }
                }
                if(md_type_ != MBEDTLS_MD_NONE) {
                    message_digest_ = md_factory_->create();
                }
                return std::unique_ptr<Result<void>>(ResultBuilder<void, void>().build());
            }

            std::unique_ptr<Result<void>> initSign(const AsymKey *key, SecureRandom *secure_random) override {
                verify_mode_ = false;
                return initCommon(key, secure_random);
            }

            std::unique_ptr<Result<void>> initVerify(const AsymKey *key) override {
                verify_mode_ = true;
                return initCommon(key, NULL);
            }

            std::unique_ptr<Result<void>> update(const void *buf, size_t length) override {
				if (message_digest_.get()) {
					return message_digest_->update(buf, length);
				}else{
					const unsigned char* pinbuf = (const unsigned char*)buf;
					input_buf_.insert(input_buf_.end(), &pinbuf[0], &pinbuf[length]);
				}
                return std::unique_ptr<Result<void>>(ResultBuilder<void, void>().build());
            }

            std::unique_ptr<Result<Buffer>> sign() override {
                int rc;
                std::vector<unsigned char> sign_buf(65536);
                size_t olen = sign_buf.size();
				if (message_digest_.get()) {
					std::unique_ptr<Result<Buffer>> hash_result = message_digest_->digest();
					rc = mbedtls_pk_sign(&pk_, md_type_, hash_result->result().data(), hash_result->result().size(), &sign_buf[0], &olen, Random::random_cb, secure_random_);
				} else {
					rc = mbedtls_pk_sign(&pk_, md_type_, input_buf_.data(), input_buf_.size(), &sign_buf[0], &olen, Random::random_cb, secure_random_);
				}
                if(rc)
                {
                    return std::unique_ptr<Result<Buffer>>(ResultBuilder<Buffer, exception::GeneralException>().withException().build());
                }
                return std::unique_ptr<Result<Buffer>>(new ResultImpl<Buffer, void>(sign_buf.data(), olen));
            }

            std::unique_ptr<Result<bool>> verify(const unsigned char *signature, size_t length) override {
                int rc;
				if (message_digest_.get()) {
					std::unique_ptr<Result<Buffer>> hash_result = message_digest_->digest();
					rc = mbedtls_pk_verify(&pk_, md_type_, hash_result->result().data(), hash_result->result().size(), signature, length);
				} else {
					rc = mbedtls_pk_verify(&pk_, md_type_, input_buf_.data(), input_buf_.size(), signature, length);
				}
				if (rc == MBEDTLS_ERR_ECP_VERIFY_FAILED)
					return std::unique_ptr<Result<bool>>(ResultBuilder<bool, void>(false).build());
                if(rc)
                    return std::unique_ptr<Result<bool>>(new ResultImpl<bool, exception::GeneralException>(false));
                return std::unique_ptr<Result<bool>>(ResultBuilder<bool, void>(true).build());
            }

        };

        std::unique_ptr<Signature> MbedcryptoSignFactory::create() {
            return std::unique_ptr<Signature>(new MbedcryptoSign(provider_, pk_type_, md_type_, md_factory_));
        }
    } // namespace mbedcrypto

} // namespace jcp

