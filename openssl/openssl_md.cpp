/**
 * @file	openssl_md_sha.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/08/14
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#include "openssl_md.hpp"

#include "../internal/key_accessor.hpp"

#include "../exception/general.hpp"

#include <openssl/hmac.h>
#include <openssl/err.h>

namespace jcp {

    namespace openssl {

        class OpensslMessageDigest : public MessageDigest {
        protected:
			const EVP_MD* md_;
			
			std::unique_ptr<EVP_MD_CTX, void(*)(EVP_MD_CTX*)> ctx_;

			unsigned long last_err_;

        public:
            OpensslMessageDigest(Provider *provider, const EVP_MD* md)
                    : MessageDigest(provider), md_(md), ctx_(EVP_MD_CTX_create(), EVP_MD_CTX_destroy), last_err_(0)
            {
				int rc;
				rc = EVP_DigestInit_ex(ctx_.get(), md_, NULL);
				if (rc != 1) {
					last_err_ = ERR_get_error();
				}
            }

            virtual ~OpensslMessageDigest() {
            }

        public:
            int digest_size() override {
				return EVP_MD_size(md_);
            }
            std::unique_ptr<Result<void>> update(const void *buf, size_t length) override {
				int rc;

				if (last_err_ != 0) {
					return std::unique_ptr<Result<void>>(ResultBuilder<void, exception::GeneralException>().withException("EVP_DigestInit_ex failed", last_err_).build());
				}

				rc = EVP_DigestUpdate(ctx_.get(), buf, length);
				if (rc != 1) {
					return std::unique_ptr<Result<void>>(ResultBuilder<void, exception::GeneralException>().withException("EVP_DigestUpdate failed", ERR_get_error()).build());
				}
                return std::unique_ptr<Result<void>>(ResultBuilder<void, void>().build());
            }

            std::unique_ptr<Result<void>> digest(unsigned char *buf) override {
				int rc;
				unsigned int outl = 0;
				rc = EVP_DigestFinal_ex(ctx_.get(), buf, &outl);
				if (rc != 1) {
					return std::unique_ptr<Result<void>>(ResultBuilder<void, exception::GeneralException>().withException("EVP_DigestFinal_ex failed", ERR_get_error()).build());
				}
                return std::unique_ptr<Result<void>>(ResultBuilder<void, void>().build());
            }

            std::unique_ptr<Result<Buffer>> digest() override {
				int rc;
				unsigned int outl = 0;
				std::unique_ptr<ResultImpl<Buffer, void>> result(ResultBuilder<Buffer, void>(digest_size()).build());
				rc = EVP_DigestFinal_ex(ctx_.get(), result->result().buffer(), &outl);
				if (rc != 1) {
					return std::unique_ptr<Result<Buffer>>(ResultBuilder<Buffer, exception::GeneralException>().withException("EVP_DigestFinal_ex failed", ERR_get_error()).build());
				}
                return std::move(result);
            }
        };

		class OpensslMac : public Mac {
		protected:
			const EVP_MD* md_;

			std::unique_ptr<EVP_MD_CTX, void(*)(EVP_MD_CTX*)> ctx_;

			std::unique_ptr<EVP_PKEY, void(*)(EVP_PKEY*)> pkey_;

		public:
			OpensslMac(Provider* provider, const EVP_MD* md)
				: Mac(provider), md_(md), ctx_(EVP_MD_CTX_create(), EVP_MD_CTX_destroy), pkey_(NULL, EVP_PKEY_free)
			{
			}

			virtual ~OpensslMac() {
			}

		public:
			std::unique_ptr<Result<void>> init(EVP_PKEY *pkey) {
				int rc = EVP_DigestSignInit(ctx_.get(), NULL, md_, NULL, pkey);
				if (rc != 1) {
					return std::unique_ptr<Result<void>>(ResultBuilder<void, exception::GeneralException>().withException("EVP_DigestSignInit failed", ERR_get_error()).build());
				}
				return std::unique_ptr<Result<void>>(ResultBuilder<void, void>().build());
			}

			std::unique_ptr<Result<void>> init(SecretKey* key) override {
				const std::vector<unsigned char>& plain_key = internal::KeyAccessor::getPlainKey(key);
				pkey_.reset(EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, plain_key.data(), plain_key.size()));
				return init(pkey_.get());
			}

			int digest_size() const override {
				return EVP_MD_size(md_);
			}

			std::unique_ptr<Result<void>> update(const void* buf, size_t length) override {
				int rc = EVP_DigestSignUpdate(ctx_.get(), buf, length);
				if (rc != 1) {
					return std::unique_ptr<Result<void>>(ResultBuilder<void, exception::GeneralException>().withException("EVP_DigestUpdate failed", ERR_get_error()).build());
				}
				return std::unique_ptr<Result<void>>(ResultBuilder<void, void>().build());
			}

			std::unique_ptr<Result<void>> digest(unsigned char* buf) override {
				int rc;
				unsigned int outl = 0;
				rc = EVP_DigestSignFinal(ctx_.get(), buf, &outl);
				if (rc != 1) {
					return std::unique_ptr<Result<void>>(ResultBuilder<void, exception::GeneralException>().withException("EVP_DigestFinal_ex failed", ERR_get_error()).build());
				}
				return std::unique_ptr<Result<void>>(ResultBuilder<void, void>().build());
			}

			std::unique_ptr<Result<Buffer>> digest() override {
				int rc;
				unsigned int outl = 0;
				std::unique_ptr<ResultImpl<Buffer, void>> result(ResultBuilder<Buffer, void>(digest_size()).build());
				rc = EVP_DigestSignFinal(ctx_.get(), result->result().buffer(), &outl);
				if (rc != 1) {
					return std::unique_ptr<Result<Buffer>>(ResultBuilder<Buffer, exception::GeneralException>().withException("EVP_DigestFinal_ex failed", ERR_get_error()).build());
				}
				return std::move(result);
			}

			void reset() override {
				EVP_DigestInit_ex(ctx_.get(), md_, NULL);
			}
		};

        std::unique_ptr<MessageDigest> OpensslMessageDigestFactory::create() {
            return std::unique_ptr<OpensslMessageDigest>(new OpensslMessageDigest(provider_, md_));
        }

        std::unique_ptr<Mac> OpensslMacFactory::create() {
            return std::unique_ptr<OpensslMac>(new OpensslMac(provider_, md_));
        }


    } // namespace openssl

} // namespace jcp



