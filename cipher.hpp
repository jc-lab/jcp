/**
 * @file	cipher.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef __JCP_CIPHER_H__
#define __JCP_CIPHER_H__

#include <memory>
#include <vector>

#include "result.hpp"
#include "buffer.hpp"
#include "secret_key.hpp"
#include "asym_key.hpp"
#include "algo_param_spec.hpp"

namespace jcp {

	class Provider;

	class SecureRandom;

    class Cipher {
    protected:
        Provider *provider_;

    public:
		enum Mode {
			ENCRYPT_MODE = 1,
			DECRYPT_MODE = 2,
		};

        static std::unique_ptr<Cipher> getInstance(const char *name, std::shared_ptr<Provider> provider = NULL);
        static std::unique_ptr<Cipher> getInstance(uint32_t algo_id, std::shared_ptr<Provider> provider = NULL);

        Cipher(Provider *provider) : provider_(provider) {}
        Provider *getProvider() const { return provider_; }

        /**
         *
         * @param mode
         * @param key
         * @param algorithmParameterSpec
         * @return
         * @throws InvalidKeyException
         * @throws InvalidAlgorithmParameterException
         */
        virtual std::unique_ptr< Result<void> > init(int mode, const SecretKey *key, const AlgorithmParameterSpec *algorithmParameterSpec = NULL, SecureRandom *secure_random = NULL) = 0;
        virtual std::unique_ptr< Result<void> > init(int mode, const AsymKey *key, const AlgorithmParameterSpec *algorithmParameterSpec = NULL, SecureRandom *secure_random = NULL) = 0;

        /**
         * Returns the block size (in bytes).
         *
         * @return the block size (in bytes), or 0 if the underlying algorithm is not a block cipher
         */
        virtual int getBlockSize() = 0;
        virtual std::unique_ptr< Result<void> > updateAAD(const void *auth, size_t length) = 0;
        virtual std::unique_ptr< Result<Buffer> > update(const void *buf, size_t length) = 0;
        virtual std::unique_ptr< Result<Buffer> > doFinal() = 0;
        std::unique_ptr< Result<Buffer> > doFinal(const void *buf, size_t length) {
            std::unique_ptr< Result<Buffer> > update_result = update(buf, length);
            if(update_result->exception())
                return std::move(update_result);

            std::unique_ptr< Result<Buffer> > final_result = doFinal(buf, length);
            if(update_result->exception())
                return std::move(update_result);

            std::unique_ptr< NoExceptionResult<Buffer> > result_with_buf(new NoExceptionResult<Buffer>(update_result->result().size() + final_result->result().size()));
            unsigned char *poutbuf = result_with_buf->result()->buffer();
            memcpy(poutbuf, update_result->result().data(), update_result->result().size());
            poutbuf += update_result->result().size();
            memcpy(poutbuf, final_result->result().data(), final_result->result().size());
            return std::move(result_with_buf);
        }

        virtual std::unique_ptr<Buffer> getIv() = 0;
    };

    class CipherFactory {
    protected:
        Provider *provider_;

    public:
        CipherFactory(Provider *provider) : provider_(provider) {}

        virtual std::unique_ptr<Cipher> create() = 0;
    };

}

#endif // __JCP_CIPHER_H__
