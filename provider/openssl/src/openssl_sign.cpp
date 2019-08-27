/**
 * @file	openssl_sign.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/08/14
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#include <openssl/err.h>
#include <openssl/opensslv.h>

#include "openssl_sign.hpp"
#include "openssl_md.hpp"

#include "jcp/secure_random.hpp"
#include <jcp/exception/general.hpp>

#include "jcp/message_digest.hpp"
#include "jcp/openssl_key_utils.hpp"

#include <openssl/evp.h>

#ifdef EVP_MD_CTX_destroy
#undef EVP_MD_CTX_destroy
#define EVP_MD_CTX_destroy EVP_MD_CTX_free
#endif

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

#if OPENSSL_VERSION_NUMBER < 0x01010000
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
#else
            static void MY_EVP_PLAIN_MD_free(EVP_MD* md) {
                EVP_MD_meth_free(md);
            }

            static int MY_EVP_PLAIN_MD_update (EVP_MD_CTX* ctx, const void* data, size_t count) {
                MY_EVP_PLAIN_MD_ctx *ctximpl = (MY_EVP_PLAIN_MD_ctx*)EVP_MD_CTX_md_data(ctx);
                const unsigned char* data_bytes = (const unsigned char*)data;
                ctximpl->buf.insert(ctximpl->buf.end(), data_bytes, data_bytes + count);
                return 1;
            }
            static int MY_EVP_PLAIN_MD_final (EVP_MD_CTX* ctx, unsigned char* md) {
                MY_EVP_PLAIN_MD_ctx *ctximpl = (MY_EVP_PLAIN_MD_ctx*)EVP_MD_CTX_md_data(ctx);
                memcpy(md, ctximpl->buf.data(), ctximpl->buf.size());
                return 1;
            }
            static int MY_EVP_PLAIN_MD_copy (EVP_MD_CTX* to, const EVP_MD_CTX* from) {
                return 1;
            }
            static int MY_EVP_PLAIN_MD_init(EVP_MD_CTX* ctx) {
                MY_EVP_PLAIN_MD_ctx *ctximpl = (MY_EVP_PLAIN_MD_ctx*)EVP_MD_CTX_md_data(ctx);
                new (ctximpl) MY_EVP_PLAIN_MD_ctx();
                return 1;
            }
            static int MY_EVP_PLAIN_MD_cleanup(EVP_MD_CTX* ctx) {
                MY_EVP_PLAIN_MD_ctx *ctximpl = (MY_EVP_PLAIN_MD_ctx*)EVP_MD_CTX_md_data(ctx);
                if (ctximpl) {
                    ctximpl->~MY_EVP_PLAIN_MD_ctx();
                }
                return 1;
            }
            static void MY_EVP_PLAIN_MD_set_size(EVP_MD* md, const EVP_MD_CTX* ctx) {
                MY_EVP_PLAIN_MD_ctx *ctximpl = (MY_EVP_PLAIN_MD_ctx*)EVP_MD_CTX_md_data(ctx);
                EVP_MD_meth_set_result_size(md, ctximpl->buf.size());
            }

            void initCommon(const AsymKey *key) {
			    const ECKey *key_ec = dynamic_cast<const ECKey *>(key);
                const RSAKey *key_rsa = dynamic_cast<const RSAKey *>(key);

                OpensslKeyUtils key_utils(getProvider());
                pkey_.reset(EVP_PKEY_new());
                if (key_ec) {
                    EC_KEY *eckey = EC_KEY_new();
                    key_utils.setECKeyToPK(eckey, key_ec);
                    EVP_PKEY_set1_EC_KEY(pkey_.get(), eckey);
                } else if (key_rsa) {
                    RSA *rsa = RSA_new();
                    key_utils.setRSAKeyToPK(rsa, key_rsa);
                    EVP_PKEY_set1_RSA(pkey_.get(), rsa);
                }

                if (!md_) {
                    EVP_MD* ptr = EVP_MD_meth_new(NID_sha256, 0);
                    EVP_MD_meth_set_app_datasize(ptr, sizeof(MY_EVP_PLAIN_MD_ctx));
                    EVP_MD_meth_set_init(ptr, MY_EVP_PLAIN_MD_init);
                    EVP_MD_meth_set_update(ptr, MY_EVP_PLAIN_MD_update);
                    EVP_MD_meth_set_final(ptr, MY_EVP_PLAIN_MD_final);
                    EVP_MD_meth_set_cleanup(ptr, MY_EVP_PLAIN_MD_cleanup);

                    md_ = plain_md_.get();
                }
            }
#endif

        public:
            OpensslSign(Provider *provider, const EVP_MD* md)
                : Signature(provider), md_(md), ctx_(EVP_MD_CTX_create(), EVP_MD_CTX_destroy), pkey_(NULL, EVP_PKEY_free), plain_md_(NULL, MY_EVP_PLAIN_MD_free)
            {
            }

            jcp::Result<void> initSign(const AsymKey *key, SecureRandom *secure_random) override {
				int rc;

				verify_mode_ = false;

				initCommon(key);

				rc = EVP_DigestSignInit(ctx_.get(), NULL, md_, NULL, pkey_.get());
				if (rc != 1) {
					return jcp::Result<void>(ResultBuilder<void, exception::GeneralException>().withException("EVP_DigestSignInit failed", ERR_get_error()).build());
				}
				return ResultBuilder<void, void>().build();
            }

            jcp::Result<void> initVerify(const AsymKey *key) override {
				int rc;

				verify_mode_ = false;

				initCommon(key);

				rc = EVP_DigestVerifyInit(ctx_.get(), NULL, md_, NULL, pkey_.get());
				if (rc != 1) {
					unsigned long errnum = ERR_get_error();
					char msgbuf[128];
					ERR_error_string(errnum, msgbuf);
					return jcp::Result<void>(ResultBuilder<void, exception::GeneralException>().withException(msgbuf, errnum).build());
				}
				return ResultBuilder<void, void>().build();
            }

			jcp::Result<void> update(const void* buf, size_t length) override {
				int rc = EVP_DigestUpdate(ctx_.get(), buf, length);
				if (rc != 1) {
					return jcp::Result<void>(ResultBuilder<void, exception::GeneralException>().withException("EVP_DigestUpdate failed", ERR_get_error()).build());
				}
				return ResultBuilder<void, void>().build();
			}

            jcp::Result<Buffer> sign() override {
				int rc;
				unsigned int outl = 0;
				std::unique_ptr<ResultImpl<Buffer, void>> result_with_buf(new ResultImpl<Buffer, void>(EVP_MD_CTX_size(ctx_.get())));

				if (plain_md_) {
					MY_EVP_PLAIN_MD_set_size(plain_md_.get(), ctx_.get());
				}

				rc = EVP_DigestSignFinal(ctx_.get(), result_with_buf->result().buffer(), &outl);
				if (rc != 1) {
					return jcp::Result<Buffer>(ResultBuilder<Buffer, exception::GeneralException>().withException("EVP_DigestSignFinal failed", ERR_get_error()).build());
				}
                return jcp::Result<Buffer>(std::move(result_with_buf));
            }

            jcp::Result<bool> verify(const unsigned char *signature, size_t length) override {
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
					return jcp::Result<bool>(ResultBuilder<bool, void>(false).build());
					//return jcp::Result<void>(ResultBuilder<void, exception::GeneralException>().withException(msgbuf, errnum).build());
				}
				//if (rc)
				//	return jcp::Result<bool>(new ResultImpl<bool, exception::GeneralException>(false));
				return jcp::Result<bool>(ResultBuilder<bool, void>(true).build());
            }

        };

        std::unique_ptr<Signature> OpensslSignFactory::create() {
            return std::unique_ptr<Signature>(new OpensslSign(provider_, md_));
        }
    } // namespace src

} // namespace jcp

