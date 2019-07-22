/**
 * @file	mbedcrypto_cipher_sym.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#include "mbedcrypto_cipher_sym.hpp"

#include "../internal/key_accessor.hpp"
#include "../iv_param_spec.hpp"
#include "../gcm_param_spec.hpp"

#include "../exception/invalid_key.hpp"
#include "../exception/invalid_input.hpp"
#include "../exception/invalid_algo_param.hpp"

#include <string.h>

#ifdef BLOCK_SIZE
#undef BLOCK_SIZE
#endif
#define BLOCK_SIZE 16

namespace jcp {

    namespace mbedcrypto {

        class MbedcryptoSymCipher : public Cipher {
        protected:
            mbedtls_cipher_type_t cipher_type_;
            mbedtls_cipher_context_t ctx_;
			const std::map<int, mbedtls_cipher_type_t>* cipher_types_with_keysize_;

            int aead_tag_size_;
            bool stream_mode_;

            std::vector<unsigned char> iv_;

			int block_buf_pos_;
			unsigned char block_buf_data_[BLOCK_SIZE];

        public:
			MbedcryptoSymCipher(mbedtls_cipher_type_t cipher_type, const std::map<int, mbedtls_cipher_type_t>* cipher_types_with_keysize)
                    : cipher_type_(cipher_type), cipher_types_with_keysize_(cipher_types_with_keysize), aead_tag_size_(0), stream_mode_(false), block_buf_pos_(0)
            {
                memset(&ctx_, 0, sizeof(ctx_));
                mbedtls_cipher_init(&ctx_);
            }

            virtual ~MbedcryptoSymCipher() {
                mbedtls_cipher_free(&ctx_);
            }

        public:
            std::unique_ptr<Result<void>> init(int mode, const SecretKey *key, const AlgorithmParameterSpec *algorithmParameterSpec, SecureRandom *secure_random) override {
                int rc;
                mbedtls_operation_t op = MBEDTLS_OPERATION_NONE;
                const std::vector<unsigned char> &plain_key = internal::KeyAccessor::getPlainKey(key);
                switch(mode) {
                    case ENCRYPT_MODE:
                        op = MBEDTLS_ENCRYPT;
                        break;
                    case DECRYPT_MODE:
                        op = MBEDTLS_DECRYPT;
                        break;
                }

				if (cipher_types_with_keysize_) {
					std::map<int, mbedtls_cipher_type_t>::const_iterator iter = cipher_types_with_keysize_->find(plain_key.size() * 8);
					if (iter != cipher_types_with_keysize_->end()) {
						cipher_type_ = iter->second;
					} else {
						return std::unique_ptr<Result<void>>(new ExceptionResultImpl<void, exception::InvalidKeyException>("Invalid key size"));
					}
				}

                rc = mbedtls_cipher_setup(&ctx_, mbedtls_cipher_info_from_type(cipher_type_));
                rc = mbedtls_cipher_setkey(&ctx_, plain_key.data(), plain_key.size() * 8, op);
                switch(mbedtls_cipher_get_cipher_mode(&ctx_)) {
                    case MBEDTLS_MODE_CBC:
                    case MBEDTLS_MODE_CFB:
                    case MBEDTLS_MODE_OFB: {
                        const IvParameterSpec *ivParameterSpec = dynamic_cast<const IvParameterSpec *>(algorithmParameterSpec);
                        iv_ = ivParameterSpec->get_iv();
                        rc = mbedtls_cipher_set_iv(&ctx_, iv_.data(), iv_.size());
                    }
                        break;
                    case MBEDTLS_MODE_GCM: {
                        const GcmParameterSpec *gcmParameterSpec = dynamic_cast<const GcmParameterSpec *>(algorithmParameterSpec);
                        iv_ = gcmParameterSpec->get_iv();
                        rc = mbedtls_cipher_set_iv(&ctx_, iv_.data(), iv_.size());
                        aead_tag_size_ = gcmParameterSpec->get_t_len();
                        stream_mode_ = true;
                    }
                        break;
                }
                return std::unique_ptr<Result<void>>(new NoExceptionResult<void>());
            }

            std::unique_ptr<Result<void>> init(int mode, const AsymKey *key, const AlgorithmParameterSpec *algorithmParameterSpec, SecureRandom *secure_random) override {
                return std::unique_ptr<Result<void>>(new ExceptionResultImpl<void, exception::InvalidKeyException>());
            }

            int getBlockSize() override {
                return mbedtls_cipher_get_block_size(&ctx_);
            }

            std::unique_ptr< Result<void> > updateAAD(const void *auth, size_t length) override {
			    int rc = mbedtls_cipher_update_ad(&ctx_, (const unsigned char*)auth, length);
                if (rc)
                {
                    return std::unique_ptr< Result<void> >(new ExceptionResultImpl<void, exception::InvalidInputException>("Set Auth failed", rc));
                }
                return std::unique_ptr<Result<void>>(new NoExceptionResult<void>());
            }

            size_t floor_block_size(size_t length) {
                int x = length % BLOCK_SIZE;
                length -= x;
                return length;
            }

            size_t ceil_block_size(size_t length) {
			    if(!stream_mode_) {
                    int x = length % BLOCK_SIZE;
                    if (x) {
                        length += BLOCK_SIZE - x;
                    }
                }
                return length;
            }

            std::unique_ptr< Result<Buffer> > update(const void *buf, size_t length) override {
                const unsigned char *pinbuf = (const unsigned char*)buf;
                int rc;
                std::unique_ptr< NoExceptionResult<Buffer> > result_with_buf(new NoExceptionResult<Buffer>(floor_block_size(length)));
                unsigned char *poutbuf = result_with_buf->result()->buffer();
                size_t outbuf_remaining = result_with_buf->result()->size();
                if(block_buf_pos_)
                {
                    // If have buffered data
                    int buf_remaining = BLOCK_SIZE - block_buf_pos_;
                    if(length < buf_remaining)
                        buf_remaining = length;
                    memcpy(&block_buf_data_[block_buf_pos_], pinbuf, buf_remaining);
                    length -= buf_remaining;
                    block_buf_pos_ += buf_remaining;
                    if(block_buf_pos_ == BLOCK_SIZE)
                    {
                        size_t olen = outbuf_remaining;
                        rc = mbedtls_cipher_update(&ctx_, block_buf_data_, BLOCK_SIZE, poutbuf, &olen);
                        pinbuf += olen;
                        poutbuf += olen;
                        outbuf_remaining -= olen;
                        block_buf_pos_ = 0;
                    }
                }
                if(length > 0) {
                    int writable_len = length;
                    int left_length = length % BLOCK_SIZE;
                    if(left_length) {
                        writable_len -= left_length;
                    }
                    if (writable_len > 0) {
                        size_t olen = outbuf_remaining;
                        rc = mbedtls_cipher_update(&ctx_, pinbuf, writable_len, poutbuf, &olen);
                        pinbuf += writable_len;
                        poutbuf += writable_len;
                    }
                    if(left_length > 0) {
                        memcpy(block_buf_data_, pinbuf, left_length);
                        block_buf_pos_ = left_length;
                    }
                }
                return std::move(result_with_buf);
            }

            std::unique_ptr< Result<Buffer> > doFinal() override {
                int rc;
                std::unique_ptr< NoExceptionResult<Buffer> > result_with_buf(new NoExceptionResult<Buffer>(ceil_block_size(block_buf_pos_) + (aead_tag_size_ / 8)));
                unsigned char* poutbuf = result_with_buf->result()->buffer();
                size_t remainging_outbuf = result_with_buf->result()->size();
                if (block_buf_pos_ > 0) {
                    size_t olen = remainging_outbuf;
                    rc = mbedtls_cipher_update(&ctx_, block_buf_data_, block_buf_pos_, poutbuf, &olen);
                    poutbuf += olen;
                }
                if(aead_tag_size_ > 0) {
                    mbedtls_cipher_write_tag(&ctx_, poutbuf, aead_tag_size_ / 8);
                }
                return std::move(result_with_buf);
            }

            std::unique_ptr<Buffer> getIv() override {
                return std::unique_ptr<Buffer>(new Buffer(iv_));
            }

        };

        std::unique_ptr<Cipher> MbedcryptoSymCipherFactory::create() {
            return std::unique_ptr<MbedcryptoSymCipher>(new MbedcryptoSymCipher(cipher_type_, (cipher_type_ == MBEDTLS_CIPHER_NONE) ? &cipher_types_with_keysize_ : NULL));
        }


    } // namespace mbedcrypto

} // namespace jcp



