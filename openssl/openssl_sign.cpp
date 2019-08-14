/**
 * @file	openssl_sign.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/08/14
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#include <openssl/err.h>

#include "openssl_sign.hpp"
#include "openssl_md.hpp"

#include "../secure_random.hpp"
#include "../exception/general.hpp"

#include "../message_digest.hpp"

#include <openssl/evp.h>

namespace jcp {

    namespace openssl {

        class OpensslSign : public Signature {
        private:
			const EVP_MD* md_;

			std::unique_ptr<EVP_MD_CTX, void(*)(EVP_MD_CTX*)> ctx_;

			std::unique_ptr<EVP_PKEY, void(*)(EVP_PKEY*)> pkey_;

			std::unique_ptr<EVP_MD, void(*)(EVP_MD*)> plain_md_;

            bool verify_mode_;

            std::unique_ptr<SecureRandom> local_secure_random_;
            SecureRandom *secure_random_;

			struct MY_EVP_PLAIN_MD_ctx {
				std::vector<unsigned char> buf;
			};

			static void MY_EVP_PLAIN_MD_free(EVP_MD* md) {
				free(md);
			}

			static int MY_EVP_PLAIN_MD_update (EVP_MD_CTX* ctx, const void* data, size_t count) {
				MY_EVP_PLAIN_MD_ctx* ctximpl = (MY_EVP_PLAIN_MD_ctx*)ctx->md_data;
				const unsigned char* data_bytes = (const unsigned char*)data;
				ctximpl->buf.insert(ctximpl->buf.end(), data_bytes, data_bytes + count);
				return 1;
			}
			static int MY_EVP_PLAIN_MD_final (EVP_MD_CTX* ctx, unsigned char* md) {
				MY_EVP_PLAIN_MD_ctx* ctximpl = (MY_EVP_PLAIN_MD_ctx*)ctx->md_data;
				memcpy(md, ctximpl->buf.data(), ctximpl->buf.size());
				return 1;
			}
			static int MY_EVP_PLAIN_MD_copy (EVP_MD_CTX* to, const EVP_MD_CTX* from) {
				return 1;
			}
			static int MY_EVP_PLAIN_MD_init(EVP_MD_CTX* ctx) {
				ctx->md_data = new MY_EVP_PLAIN_MD_ctx();
				ctx->update = MY_EVP_PLAIN_MD_update;
				return 1;
			}
			static int MY_EVP_PLAIN_MD_cleanup(EVP_MD_CTX* ctx) {
				if (ctx->md_data) {
					delete ctx->md_data;
					ctx->md_data = NULL;
				}
				return 1;
			}
			static void MY_EVP_PLAIN_MD_set_size(EVP_MD* md, const EVP_MD_CTX* ctx) {
				const MY_EVP_PLAIN_MD_ctx* ctximpl = (const MY_EVP_PLAIN_MD_ctx*)ctx->md_data;
				md->md_size = ctximpl->buf.size();
			}

        public:
            OpensslSign(Provider *provider, const EVP_MD* md)
                : Signature(provider), md_(md), ctx_(EVP_MD_CTX_create(), EVP_MD_CTX_destroy), pkey_(NULL, EVP_PKEY_free), plain_md_(NULL, MY_EVP_PLAIN_MD_free)
            {
            }

			void initCommon() {
				if (!md_) {
					EVP_MD* ptr = (EVP_MD*)malloc(sizeof(EVP_MD));
					memset(ptr, 0, sizeof(EVP_MD));
					plain_md_.reset(ptr);
					ptr->type = NID_sha256;
					ptr->init = MY_EVP_PLAIN_MD_init;
					ptr->update = MY_EVP_PLAIN_MD_update;
					ptr->final = MY_EVP_PLAIN_MD_final;
					ptr->copy = NULL;
					ptr->cleanup = MY_EVP_PLAIN_MD_cleanup;

					md_ = plain_md_.get();
				}
			}

            std::unique_ptr<Result<void>> initSign(const AsymKey *key, SecureRandom *secure_random) override {
				int rc;

				verify_mode_ = false;
				pkey_ = key->getOpensslEVPPKey();

				initCommon();

				rc = EVP_DigestSignInit(ctx_.get(), NULL, md_, NULL, pkey_.get());
				if (rc != 1) {
					return std::unique_ptr<Result<void>>(ResultBuilder<void, exception::GeneralException>().withException("EVP_DigestSignInit failed", ERR_get_error()).build());
				}
				return std::unique_ptr<Result<void>>(ResultBuilder<void, void>().build());
            }

            std::unique_ptr<Result<void>> initVerify(const AsymKey *key) override {
				int rc;

				verify_mode_ = false;
				pkey_ = key->getOpensslEVPPKey();

				initCommon();

				rc = EVP_DigestVerifyInit(ctx_.get(), NULL, md_, NULL, pkey_.get());
				if (rc != 1) {
					unsigned long errnum = ERR_get_error();
					char msgbuf[128];
					ERR_error_string(errnum, msgbuf);
					return std::unique_ptr<Result<void>>(ResultBuilder<void, exception::GeneralException>().withException(msgbuf, errnum).build());
				}
				return std::unique_ptr<Result<void>>(ResultBuilder<void, void>().build());
            }

			std::unique_ptr<Result<void>> update(const void* buf, size_t length) override {
				int rc = EVP_DigestUpdate(ctx_.get(), buf, length);
				if (rc != 1) {
					return std::unique_ptr<Result<void>>(ResultBuilder<void, exception::GeneralException>().withException("EVP_DigestUpdate failed", ERR_get_error()).build());
				}
				return std::unique_ptr<Result<void>>(ResultBuilder<void, void>().build());
			}

            std::unique_ptr<Result<Buffer>> sign() override {
				int rc;
				unsigned int outl = 0;
				std::unique_ptr<ResultImpl<Buffer, void>> result(ResultBuilder<Buffer, void>(EVP_MD_CTX_size(ctx_.get())).build());

				if (plain_md_) {
					MY_EVP_PLAIN_MD_set_size(plain_md_.get(), ctx_.get());
				}

				rc = EVP_DigestSignFinal(ctx_.get(), result->result().buffer(), &outl);
				if (rc != 1) {
					return std::unique_ptr<Result<Buffer>>(ResultBuilder<Buffer, exception::GeneralException>().withException("EVP_DigestSignFinal failed", ERR_get_error()).build());
				}
				return std::move(result);
            }

            std::unique_ptr<Result<bool>> verify(const unsigned char *signature, size_t length) override {
				int rc;
				unsigned int outl = 0;

				if (plain_md_) {
					MY_EVP_PLAIN_MD_set_size(plain_md_.get(), ctx_.get());
				}

				rc = EVP_DigestVerifyFinal(ctx_.get(), signature, length);
				if (rc != 1) {
					unsigned long errnum = ERR_get_error();
					char msgbuf[128];
					ERR_error_string(errnum, msgbuf);
					return std::unique_ptr<Result<bool>>(ResultBuilder<bool, void>(false).build());
					//return std::unique_ptr<Result<void>>(ResultBuilder<void, exception::GeneralException>().withException(msgbuf, errnum).build());
				}
				//if (rc)
				//	return std::unique_ptr<Result<bool>>(new ResultImpl<bool, exception::GeneralException>(false));
				return std::unique_ptr<Result<bool>>(ResultBuilder<bool, void>(true).build());
            }

        };

        std::unique_ptr<Signature> OpensslSignFactory::create() {
            return std::unique_ptr<Signature>(new OpensslSign(provider_, md_));
        }
    } // namespace openssl

} // namespace jcp

