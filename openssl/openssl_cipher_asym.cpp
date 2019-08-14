/**
 * @file	openssl_cipher_asym.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/08/14
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#include "openssl_cipher_asym.hpp"

#include "../internal/key_accessor.hpp"
#include "../exception/general.hpp"
#include "../exception/invalid_input.hpp"
#include "../exception/invalid_key.hpp"

#include "../secure_random.hpp"

#include <vector>

namespace jcp {

    namespace openssl {

        class OpensslAsymCipher : public Cipher {
        private:
			enum Algorithm {
				ALG_UNKNOWN = 0,
				ALGO_RSA = 1,
			};

            int pk_type_;
			int padding_type_;
			Algorithm algo_;

			std::unique_ptr<EVP_PKEY, void(*)(EVP_PKEY*)> pk_;
			std::unique_ptr<EVP_CIPHER_CTX, void(*)(EVP_CIPHER_CTX*)> cipher_ctx_;
            bool encrypt_mode_;

            std::vector<unsigned char> input_buf_;

            std::unique_ptr<SecureRandom> local_secure_random_;
            SecureRandom *secure_random_;

        public:
            OpensslAsymCipher(Provider *provider, int pk_type, int padding_type) : Cipher(provider), pk_type_(pk_type), padding_type_(padding_type), secure_random_(NULL),
				algo_(ALG_UNKNOWN), pk_(NULL, EVP_PKEY_free), cipher_ctx_(NULL, EVP_CIPHER_CTX_free) {
            }

            std::unique_ptr<Result<void>> init(int mode, const SecretKey *key, const AlgorithmParameterSpec *algorithmParameterSpec, SecureRandom *secure_random) override {
                return std::unique_ptr<Result<void>>(ResultBuilder<void, exception::InvalidKeyException>().withException().build());
            }

            std::unique_ptr<Result<void>> init(int mode, const AsymKey *key, const AlgorithmParameterSpec *algorithmParameterSpec, SecureRandom *secure_random) override {
				int rc;
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
				pk_.reset(EVP_PKEY_new());
				cipher_ctx_.reset(EVP_CIPHER_CTX_new());
				EVP_PKEY_set_type(pk_.get(), pk_type_);

				if (key->isRSAKey())
				{
					RSA* rsa = (RSA*)key->getOpensslRSAKey();
					rc = EVP_PKEY_set1_RSA(pk_.get(), rsa);
				} else {
					return std::unique_ptr<Result<void>>(ResultBuilder<void, exception::InvalidKeyException>().withException("Not support key type").build());
				}
				if (rc != 1)
				{
					return std::unique_ptr<Result<void>>(ResultBuilder<void, exception::InvalidKeyException>().withException("set key failed", rc).build());
				}

				return std::unique_ptr<Result<void>>(ResultBuilder<void, void>().build());
            }

            int getBlockSize() override {
                return 0;
            }

            std::unique_ptr<Result<void>> updateAAD(const void *auth, size_t length) override {
                return std::unique_ptr<Result<void>>(ResultBuilder<void, exception::InvalidInputException>().withException().build());
            }

            std::unique_ptr<Result<Buffer>> update(const void *buf, size_t length) override {
                const unsigned char *pin = (const unsigned char*)buf;
                input_buf_.insert(input_buf_.end(), &pin[0], &pin[length]);
                return std::unique_ptr<Result<Buffer>>(ResultBuilder<Buffer, void>().build());
            }

            std::unique_ptr<Result<Buffer>> doFinal() override {
                int rc;
                std::vector<unsigned char> outbuf;

				if (algo_ == ALGO_RSA) {
					RSA* rsa = EVP_PKEY_get1_RSA(pk_.get());
					outbuf.resize(RSA_size(rsa));
					if (encrypt_mode_) {
						rc = RSA_public_encrypt(input_buf_.size(), input_buf_.data(), &outbuf[0], rsa, padding_type_);
					}else{
						rc = RSA_private_decrypt(input_buf_.size(), input_buf_.data(), &outbuf[0], rsa, padding_type_);
					}
					RSA_free(rsa);
				}
                if(rc < 0) {
                    return std::unique_ptr<Result<Buffer>>(ResultBuilder<Buffer, exception::InvalidInputException>().withException("pk failed", rc).build());
                }
				outbuf.resize(rc);
                return std::unique_ptr<Result<Buffer>>(ResultBuilder<Buffer, void>(outbuf).build());
            }

            std::unique_ptr<Buffer> getIv() override {
				return NULL;
            }
        };

        std::unique_ptr<Cipher> OpensslAsymCipherFactory::create() {
			return std::unique_ptr<Cipher>(new OpensslAsymCipher(provider_, pk_type_, padding_type_));
        }

    } // namespace openssl

} // namespace jcp



