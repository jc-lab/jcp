/**
 * @file	openssl_cipher_aes.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/08/14
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#ifndef __JCP_OPENSSL_OPENSSL_CIPHER_SYM_H__
#define __JCP_OPENSSL_OPENSSL_CIPHER_SYM_H__

#include "../provider.hpp"
#include "../cipher.hpp"

#include <initializer_list>

namespace jcp {

    namespace openssl {

        class OpensslSymCipherFactory : public CipherFactory {
        private:
			const EVP_CIPHER* cipher_type_;
			std::map<int, const EVP_CIPHER*> cipher_types_with_keysize_;

        public:
			OpensslSymCipherFactory(Provider *provider, const EVP_CIPHER* cipher_type) : CipherFactory(provider), cipher_type_(cipher_type) {}

			OpensslSymCipherFactory(Provider *provider, bool dummy, const std::initializer_list< std::pair<const int, const EVP_CIPHER*> > &arg) : CipherFactory(provider), cipher_type_(NULL), cipher_types_with_keysize_(arg) {}

            std::unique_ptr<Cipher> create() override;
        };

    }

} // namespace jcp

#endif // __JCP_OPENSSL_OPENSSL_CIPHER_SYM_H__
