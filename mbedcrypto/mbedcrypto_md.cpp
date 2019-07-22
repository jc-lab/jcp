/**
 * @file	mbedcrypto_md_sha.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#include "mbedcrypto_md.hpp"

#include "../internal/key_accessor.hpp"

#include <mbedtls/md.h>

namespace jcp {

    namespace mbedcrypto {

        class MbedcryptoMessageDigest : public MessageDigest {
        protected:
            mbedtls_md_context_t ctx_;
            mbedtls_md_type_t md_type_;

        public:
            MbedcryptoMessageDigest(mbedtls_md_type_t md_type)
                    : md_type_(md_type)
            {
                mbedtls_md_init(&ctx_);
                mbedtls_md_setup(&ctx_, mbedtls_md_info_from_type(md_type), 0);
                mbedtls_md_starts(&ctx_);
            }

            virtual ~MbedcryptoMessageDigest() {
                mbedtls_md_free(&ctx_);
            }

        public:
            int digest_size() override {
                return mbedtls_md_get_size(mbedtls_md_info_from_type(md_type_));
            }
            std::unique_ptr<Result<void>> update(const void *buf, size_t length) override {
                mbedtls_md_update(&ctx_, (const unsigned char*)buf, length);
                return std::unique_ptr<Result<void>>(new NoExceptionResult<void>());
            }

            std::unique_ptr<Result<void>> digest(unsigned char *buf) override {
                mbedtls_md_finish(&ctx_, buf);
                return std::unique_ptr<Result<void>>(new NoExceptionResult<void>());
            }

            std::unique_ptr<Result<Buffer>> digest() override {
                std::unique_ptr<NoExceptionResult<Buffer>> result(new NoExceptionResult<Buffer>(digest_size()));
                mbedtls_md_finish(&ctx_, result->result()->buffer());
                return std::move(result);
            }
        };

        class MbedcryptoMac : public Mac {
        protected:
            mbedtls_md_context_t ctx_;
            mbedtls_md_type_t md_type_;

        public:
            MbedcryptoMac(mbedtls_md_type_t md_type)
                    : md_type_(md_type)
            {
                mbedtls_md_init(&ctx_);
                mbedtls_md_setup(&ctx_, mbedtls_md_info_from_type(md_type), 1);
            }

            virtual ~MbedcryptoMac() {
                mbedtls_md_free(&ctx_);
            }

        public:
            void init(SecretKey *key) override {
                const std::vector<unsigned char> &plain_key = internal::KeyAccessor::getPlainKey(key);
                mbedtls_md_hmac_starts(&ctx_, &plain_key[0], plain_key.size());
            }

            int digest_size() override {
                return mbedtls_md_get_size(mbedtls_md_info_from_type(md_type_));
            }

            std::unique_ptr<Result<void>> update(const void *buf, size_t length) override {
                mbedtls_md_hmac_update(&ctx_, (const unsigned char*)buf, length);
                return std::unique_ptr<Result<void>>(new NoExceptionResult<void>());
            }

            std::unique_ptr<Result<void>> digest(unsigned char *buf) override {
                mbedtls_md_hmac_finish(&ctx_, buf);
                return std::unique_ptr<Result<void>>(new NoExceptionResult<void>());
            }

            std::unique_ptr<Result<Buffer>> digest() override {
                std::unique_ptr<NoExceptionResult<Buffer>> result(new NoExceptionResult<Buffer>());
                mbedtls_md_hmac_finish(&ctx_, result->result()->resize(digest_size()));
                return std::move(result);
            }

        };

        std::unique_ptr<MessageDigest> MbedcryptoMessageDigestFactory::create() {
            return std::unique_ptr<MbedcryptoMessageDigest>(new MbedcryptoMessageDigest(type_));
        }

        std::unique_ptr<Mac> MbedcryptoMacFactory::create() {
            return std::unique_ptr<MbedcryptoMac>(new MbedcryptoMac(type_));
        }


    } // namespace mbedcrypto

} // namespace jcp



