/**
 * @file	openssl_provider.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/08/14
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include "openssl_provider.hpp"
#include "../cipher_algo.hpp"
#include "../message_digest_algo.hpp"
#include "../mac_algo.hpp"
#include "../key_agreement_algo.hpp"
#include "../signature_algo.hpp"
#include "../secret_key_factory_algo.hpp"

#include "openssl_securerandom.hpp"
#include "openssl_cipher_sym.hpp"
#include "openssl_cipher_asym.hpp"
#include "openssl_md.hpp"
#include "openssl_ka_ecdh.hpp"
#include "openssl_sign.hpp"
#include "openssl_pbkdf2_skf.hpp"

#include <openssl/evp.h>

namespace jcp {

    OpensslProvider::OpensslProvider()
    {
		setSecureRandomFactory(std::unique_ptr<SecureRandomFactory>(new openssl::OpensslSecureRandomFactory(this)));

		addCipherAlgorithm(&CipherAlgorithm::AesEcbNoPadding, std::unique_ptr<openssl::OpensslSymCipherFactory>(new openssl::OpensslSymCipherFactory(this, true, {
			{128, EVP_aes_128_ecb()},
			{192, EVP_aes_192_ecb()},
			{256, EVP_aes_256_ecb()}
			})));
		addCipherAlgorithm(&CipherAlgorithm::AesCbcNoPadding, std::unique_ptr<openssl::OpensslSymCipherFactory>(new openssl::OpensslSymCipherFactory(this, true, {
			{128, EVP_aes_128_cbc()},
			{192, EVP_aes_192_cbc()},
			{256, EVP_aes_256_cbc()}
			})));
		addCipherAlgorithm(&CipherAlgorithm::AesGcmNoPadding, std::unique_ptr<openssl::OpensslSymCipherFactory>(new openssl::OpensslSymCipherFactory(this, true, {
			{128, EVP_aes_128_gcm()},
			{192, EVP_aes_192_gcm()},
			{256, EVP_aes_256_gcm()}
			})));

		addCipherAlgorithm(&CipherAlgorithm::RsaEcbOaepPadding, std::unique_ptr<openssl::OpensslAsymCipherFactory>(new openssl::OpensslAsymCipherFactory(this, EVP_PKEY_RSA, RSA_PKCS1_OAEP_PADDING)));
		
		openssl::OpensslMessageDigestFactory* sha1Factory = new openssl::OpensslMessageDigestFactory(this, EVP_sha1());
        addMessageDigestAlgorithm(&MessageDigestAlgorithm::SHA_1, std::unique_ptr<openssl::OpensslMessageDigestFactory>(sha1Factory));
		openssl::OpensslMessageDigestFactory* sha224Factory = new openssl::OpensslMessageDigestFactory(this, EVP_sha224());
        addMessageDigestAlgorithm(&MessageDigestAlgorithm::SHA_224, std::unique_ptr<openssl::OpensslMessageDigestFactory>(sha224Factory));
		openssl::OpensslMessageDigestFactory* sha256Factory = new openssl::OpensslMessageDigestFactory(this, EVP_sha256());
        addMessageDigestAlgorithm(&MessageDigestAlgorithm::SHA_256, std::unique_ptr<openssl::OpensslMessageDigestFactory>(sha256Factory));
		openssl::OpensslMessageDigestFactory* sha384Factory = new openssl::OpensslMessageDigestFactory(this, EVP_sha384());
        addMessageDigestAlgorithm(&MessageDigestAlgorithm::SHA_384, std::unique_ptr<openssl::OpensslMessageDigestFactory>(sha384Factory));
		openssl::OpensslMessageDigestFactory* sha512Factory = new openssl::OpensslMessageDigestFactory(this, EVP_sha512());
        addMessageDigestAlgorithm(&MessageDigestAlgorithm::SHA_512, std::unique_ptr<openssl::OpensslMessageDigestFactory>(sha512Factory));

        openssl::OpensslMacFactory *hmacSha1Factory = new openssl::OpensslMacFactory(this, EVP_sha1());
        addMacAlgorithm(&MacAlgorithm::HmacSHA1, std::unique_ptr<openssl::OpensslMacFactory>(hmacSha1Factory));
        openssl::OpensslMacFactory *hmacSha224Factory = new openssl::OpensslMacFactory(this, EVP_sha224());
        addMacAlgorithm(&MacAlgorithm::HmacSHA224, std::unique_ptr<openssl::OpensslMacFactory>(hmacSha224Factory));
        openssl::OpensslMacFactory *hmacSha256Factory = new openssl::OpensslMacFactory(this, EVP_sha256());
        addMacAlgorithm(&MacAlgorithm::HmacSHA256, std::unique_ptr<openssl::OpensslMacFactory>(hmacSha256Factory));
        openssl::OpensslMacFactory *hmacSha384Factory = new openssl::OpensslMacFactory(this, EVP_sha384());
        addMacAlgorithm(&MacAlgorithm::HmacSHA384, std::unique_ptr<openssl::OpensslMacFactory>(hmacSha384Factory));
        openssl::OpensslMacFactory *hmacSha512Factory = new openssl::OpensslMacFactory(this, EVP_sha512());
        addMacAlgorithm(&MacAlgorithm::HmacSHA512, std::unique_ptr<openssl::OpensslMacFactory>(hmacSha512Factory));

		addKeyAgreementAlgorithm(&KeyAgreementAlgorithm::ECDH, std::unique_ptr<openssl::OpensslKaEcdhFactory>(new openssl::OpensslKaEcdhFactory(this)));

        addSignatureAlgorithm(&SignatureAlgorithm::NONEwithECDSA, std::unique_ptr<openssl::OpensslSignFactory>(new openssl::OpensslSignFactory(this, NULL)));
        addSignatureAlgorithm(&SignatureAlgorithm::SHA1withECDSA, std::unique_ptr<openssl::OpensslSignFactory>(new openssl::OpensslSignFactory(this, EVP_sha1())));
        addSignatureAlgorithm(&SignatureAlgorithm::SHA224withECDSA, std::unique_ptr<openssl::OpensslSignFactory>(new openssl::OpensslSignFactory(this, EVP_sha224())));
        addSignatureAlgorithm(&SignatureAlgorithm::SHA256withECDSA, std::unique_ptr<openssl::OpensslSignFactory>(new openssl::OpensslSignFactory(this, EVP_sha256())));
        addSignatureAlgorithm(&SignatureAlgorithm::SHA384withECDSA, std::unique_ptr<openssl::OpensslSignFactory>(new openssl::OpensslSignFactory(this, EVP_sha384())));
        addSignatureAlgorithm(&SignatureAlgorithm::SHA512withECDSA, std::unique_ptr<openssl::OpensslSignFactory>(new openssl::OpensslSignFactory(this, EVP_sha512())));

		addSignatureAlgorithm(&SignatureAlgorithm::NONEwithRSA, std::unique_ptr<openssl::OpensslSignFactory>(new openssl::OpensslSignFactory(this, NULL)));
		addSignatureAlgorithm(&SignatureAlgorithm::SHA1withRSA, std::unique_ptr<openssl::OpensslSignFactory>(new openssl::OpensslSignFactory(this, EVP_sha1())));
		addSignatureAlgorithm(&SignatureAlgorithm::SHA224withRSA, std::unique_ptr<openssl::OpensslSignFactory>(new openssl::OpensslSignFactory(this, EVP_sha224())));
		addSignatureAlgorithm(&SignatureAlgorithm::SHA256withRSA, std::unique_ptr<openssl::OpensslSignFactory>(new openssl::OpensslSignFactory(this, EVP_sha256())));
		addSignatureAlgorithm(&SignatureAlgorithm::SHA384withRSA, std::unique_ptr<openssl::OpensslSignFactory>(new openssl::OpensslSignFactory(this, EVP_sha384())));
		addSignatureAlgorithm(&SignatureAlgorithm::SHA512withRSA, std::unique_ptr<openssl::OpensslSignFactory>(new openssl::OpensslSignFactory(this, EVP_sha512())));
		
        addSecretKeyFactoryAlgorithm(&SecretKeyFactoryAlgorithm::PBKDF2WithHmacSHA1, std::unique_ptr<openssl::OpensslPBKDF2SecretKeyFactory>(new openssl::OpensslPBKDF2SecretKeyFactory(this, hmacSha1Factory)));
        addSecretKeyFactoryAlgorithm(&SecretKeyFactoryAlgorithm::PBKDF2WithHmacSHA224, std::unique_ptr<openssl::OpensslPBKDF2SecretKeyFactory>(new openssl::OpensslPBKDF2SecretKeyFactory(this, hmacSha224Factory)));
        addSecretKeyFactoryAlgorithm(&SecretKeyFactoryAlgorithm::PBKDF2WithHmacSHA256, std::unique_ptr<openssl::OpensslPBKDF2SecretKeyFactory>(new openssl::OpensslPBKDF2SecretKeyFactory(this, hmacSha256Factory)));
        addSecretKeyFactoryAlgorithm(&SecretKeyFactoryAlgorithm::PBKDF2WithHmacSHA384, std::unique_ptr<openssl::OpensslPBKDF2SecretKeyFactory>(new openssl::OpensslPBKDF2SecretKeyFactory(this, hmacSha384Factory)));
        addSecretKeyFactoryAlgorithm(&SecretKeyFactoryAlgorithm::PBKDF2WithHmacSHA512, std::unique_ptr<openssl::OpensslPBKDF2SecretKeyFactory>(new openssl::OpensslPBKDF2SecretKeyFactory(this, hmacSha512Factory)));
    }

} // namespace jcp

