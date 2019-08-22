/**
 * @file	openssl_cipher_sym.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/08/14
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#include "openssl_cipher_sym.hpp"

#include <jcp/iv_param_spec.hpp>
#include <jcp/gcm_param_spec.hpp>

#include <jcp/exception/invalid_key.hpp>
#include <jcp/exception/invalid_input.hpp>
#include <jcp/exception/invalid_algo_param.hpp>
#include <jcp/exception/aead_bad_tag.hpp>

#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#ifdef BLOCK_SIZE
#undef BLOCK_SIZE
#endif
#define BLOCK_SIZE 16

namespace jcp {

    namespace openssl {

        class OpensslSymCipher : public Cipher {
        protected:
            int mode_;

			const std::map<int, const EVP_CIPHER*>* cipher_types_with_keysize_;

			std::unique_ptr<EVP_CIPHER_CTX, void(*)(EVP_CIPHER_CTX*)> ctx_;
			const EVP_CIPHER* cipher_type_;

			int aead_tag_size_;
            bool stream_mode_;

            std::vector<unsigned char> iv_;
			std::vector<unsigned char> aead_tag_buf_;
			int aead_tag_pos_;

			int aead_tag_buf_update(const unsigned char* buf, size_t* plen, unsigned char* outbuf) {
				int ret = 0;

				unsigned char* tag_buf_ptr = &aead_tag_buf_[0];
				int in_offset = (*plen > aead_tag_size_) ? (*plen - aead_tag_size_) : 0;
				int in_len = *plen - in_offset;
				const unsigned char* in_ptr = &buf[in_offset];

				if (in_len < aead_tag_size_) {
					int next_size = aead_tag_pos_ + in_len;
					int del_size = (next_size > aead_tag_size_) ? (next_size - aead_tag_size_) : 0;
					int move_size = aead_tag_pos_ - del_size;
					int i, j;

					for (i = 0; i < move_size; i++) {
						outbuf[i] = tag_buf_ptr[i];
						tag_buf_ptr[i] = tag_buf_ptr[del_size + i];
					}
					ret = move_size;
					for (j = 0; j < in_len; j++) {
						tag_buf_ptr[i++] = in_ptr[j];
					}
					aead_tag_pos_ = i;
				}
				else {
					memcpy(outbuf, tag_buf_ptr, aead_tag_pos_);
					memcpy(tag_buf_ptr, in_ptr, aead_tag_size_);
					(*plen) -= aead_tag_size_;
					ret = aead_tag_pos_;
					aead_tag_pos_ = aead_tag_size_;
				}
				return ret;
			}

        public:
			OpensslSymCipher(Provider *provider, const EVP_CIPHER* cipher_type, const std::map<int, const EVP_CIPHER*>* cipher_types_with_keysize)
                    : Cipher(provider), cipher_type_(cipher_type), cipher_types_with_keysize_(cipher_types_with_keysize), aead_tag_size_(0), stream_mode_(false),
				ctx_(NULL, EVP_CIPHER_CTX_free)
            {
            }

            virtual ~OpensslSymCipher() {
            }

        public:
            jcp::Result<void> init(int mode, const SecretKey *key, const AlgorithmParameterSpec *algorithmParameterSpec, SecureRandom *secure_random) override {
                int rc;
                const std::vector<unsigned char> plain_key(key->getEncoded());

				ctx_.reset(EVP_CIPHER_CTX_new());

				if (cipher_types_with_keysize_) {
					std::map<int, const EVP_CIPHER*>::const_iterator iter = cipher_types_with_keysize_->find(plain_key.size() * 8);
					if (iter != cipher_types_with_keysize_->end()) {
						cipher_type_ = iter->second;
					}
					else {
						return jcp::Result<void>(ResultBuilder<void, exception::InvalidKeyException>().withException("Invalid key size").build());
					}
				}

				switch (mode) {
				case ENCRYPT_MODE:
					rc = EVP_CipherInit_ex(ctx_.get(), cipher_type_, NULL, NULL, NULL, 1);
					break;
				case DECRYPT_MODE:
					rc = EVP_CipherInit_ex(ctx_.get(), cipher_type_, NULL, NULL, NULL, 0);
					break;
				}
				mode_ = mode;

				switch (EVP_CIPHER_mode(cipher_type_)) {
				case EVP_CIPH_CBC_MODE:
				case EVP_CIPH_CFB_MODE:
				case EVP_CIPH_OFB_MODE: {
					const IvParameterSpec* ivParameterSpec = dynamic_cast<const IvParameterSpec*>(algorithmParameterSpec);
					iv_ = ivParameterSpec->get_iv();
				}
				break;
				case EVP_CIPH_GCM_MODE: {
					const GCMParameterSpec* gcmParameterSpec = dynamic_cast<const GCMParameterSpec*>(algorithmParameterSpec);
					iv_ = gcmParameterSpec->get_iv();
					rc = EVP_CIPHER_CTX_ctrl(ctx_.get(), EVP_CTRL_GCM_SET_IVLEN, iv_.size(), NULL);
					aead_tag_size_ = gcmParameterSpec->get_t_len() / 8;
					stream_mode_ = true;
				}
				break;
				}

				if(aead_tag_size_ > 0)
					aead_tag_buf_.resize(aead_tag_size_);

				rc = EVP_CipherInit_ex(ctx_.get(), NULL, NULL, plain_key.data(), iv_.empty() ? NULL : iv_.data(), -1);

                return ResultBuilder<void, void>().build();
            }

            jcp::Result<void> init(int mode, const AsymKey *key, const AlgorithmParameterSpec *algorithmParameterSpec, SecureRandom *secure_random) override {
                return jcp::Result<void>(ResultBuilder<void, exception::InvalidKeyException>().withException().build());
            }

            int getBlockSize() override {
                return EVP_CIPHER_CTX_block_size(ctx_.get());
            }

            jcp::Result<void> updateAAD(const void *auth, size_t length) override {
				int outl = 0;
				int rc = EVP_CipherUpdate(ctx_.get(), NULL, &outl, (const unsigned char*)auth, length);
                if (rc != 1)
                {
                    return jcp::Result<void>(ResultBuilder<void, exception::InvalidInputException>().withException("Set AAD failed", rc).build());
                }
                return ResultBuilder<void, void>().build();
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

            jcp::Result<Buffer> update(const void *buf, size_t length) override {
				const unsigned char* pinbuf = (const unsigned char*)buf;
				int rc;
				unsigned char prevbuf[128];
				int prevlen = 0;
				int outl = 0;

				if ((mode_ == DECRYPT_MODE) && aead_tag_size_) {
					prevlen = aead_tag_buf_update(pinbuf, &length, prevbuf);
				}

				std::vector<unsigned char> cur_buf;
				cur_buf.resize(prevlen + length);
				if (!cur_buf.size()) {
					return jcp::Result<Buffer>(ResultBuilder<Buffer, void>(0).build());
				}

				unsigned char* cur_buf_ptr = &cur_buf[0];
				memcpy(cur_buf_ptr, prevbuf, prevlen);
				cur_buf_ptr += prevlen;
				memcpy(cur_buf_ptr, buf, length);

				std::unique_ptr< ResultImpl<Buffer, void> > result_with_buf(new ResultImpl<Buffer, void>(cur_buf.size() + BLOCK_SIZE));
				rc = EVP_CipherUpdate(ctx_.get(), result_with_buf->result().buffer(), &outl, cur_buf.data(), cur_buf.size());
				result_with_buf->result().resize(outl);
                return jcp::Result<Buffer>(std::move(result_with_buf));
            }

            jcp::Result<Buffer> doFinal() override {
				std::unique_ptr< ResultImpl<Buffer, void> > result_with_buf(new ResultImpl<Buffer, void>(BLOCK_SIZE + aead_tag_size_));
				unsigned char* poutbuf = result_with_buf->result().buffer();

				if (aead_tag_size_ && (mode_ == DECRYPT_MODE)) {
#if defined(EVP_CTRL_AEAD_SET_TAG)
					EVP_CIPHER_CTX_ctrl(ctx_.get(), EVP_CTRL_AEAD_SET_TAG, aead_tag_buf_.size(), aead_tag_buf_.data());
#else
					EVP_CIPHER_CTX_ctrl(ctx_.get(), EVP_CTRL_GCM_SET_TAG, aead_tag_buf_.size(), aead_tag_buf_.data());
#endif
				}

				int outl = 0;
				int rc = EVP_CipherFinal_ex(ctx_.get(), poutbuf, &outl);
				if (rc != 1) {
					int ossl_eno = ERR_get_error();
					char buf[256] = {0};
					ERR_error_string(ossl_eno, buf);
					return jcp::Result<Buffer>(ResultBuilder<Buffer, exception::AEADBadTagException>().withException(buf, ossl_eno).build());
				}

				if (aead_tag_size_ && (mode_ == ENCRYPT_MODE)) {
#if defined(EVP_CTRL_AEAD_GET_TAG)
					EVP_CIPHER_CTX_ctrl(ctx_.get(), EVP_CTRL_AEAD_GET_TAG, aead_tag_size_, poutbuf + outl);
#else
					EVP_CIPHER_CTX_ctrl(ctx_.get(), EVP_CTRL_GCM_GET_TAG, aead_tag_size_, poutbuf + outl);
#endif
					outl += aead_tag_size_;
				}

				if (result_with_buf->result().size() != outl) {
					result_with_buf->result().resize(outl);
				}
				return jcp::Result<Buffer>(std::move(result_with_buf));
            }

            std::unique_ptr<Buffer> getIv() override {
                return std::unique_ptr<Buffer>(new Buffer(iv_));
            }

        };

        std::unique_ptr<Cipher> OpensslSymCipherFactory::create() {
            return std::unique_ptr<OpensslSymCipher>(new OpensslSymCipher(provider_, cipher_type_, (cipher_type_ == NULL) ? &cipher_types_with_keysize_ : NULL));
        }

    } // namespace src

} // namespace jcp



