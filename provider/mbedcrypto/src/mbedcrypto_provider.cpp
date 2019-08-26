/**
 * @file	mbedcrypto_provider.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include <jcp/security.hpp>

#include "jcp/mbedcrypto_provider.hpp"
#include "jcp/cipher_algo.hpp"
#include "jcp/message_digest_algo.hpp"
#include "jcp/mac_algo.hpp"
#include "jcp/key_agreement_algo.hpp"
#include "jcp/signature_algo.hpp"
#include "jcp/secret_key_factory_algo.hpp"
#include "jcp/key_factory_algo.hpp"
#include "jcp/key_pair_algo.hpp"

#include "mbedcrypto_securerandom.hpp"
#include "mbedcrypto_cipher_sym.hpp"
#include "mbedcrypto_cipher_asym.hpp"
#include "mbedcrypto_md.hpp"
#include "mbedcrypto_ka_ecdh.hpp"
#include "mbedcrypto_sign.hpp"
#include "mbedcrypto_key_utils.hpp"
#include "mbedcrypto_key_factory.hpp"
#include "mbedcrypto_key_pair_generator.hpp"

#include <jcp/soft/soft_pbkdf2_skf.hpp>
#include <jcp/soft/soft_hkdf_skf.hpp>

#include <mbedtls/cipher.h>

namespace jcp {

    void MbedcryptoProvider::registerTo(Security *security) {
        jcp::Security::addProvider(std::make_unique<MbedcryptoProvider>());
    }

    MbedcryptoProvider::MbedcryptoProvider()
    {
		setSecureRandomFactory(std::make_unique<mbedcrypto::MbedcryptoSecureRandomFactory>(this));
		setKeyUtils(std::make_unique<mbedcrypto::MbedcryptoKeyUtils>(this));

		addCipherAlgorithm(&CipherAlgorithm::AesEcbNoPadding, std::unique_ptr<mbedcrypto::MbedcryptoSymCipherFactory>(new mbedcrypto::MbedcryptoSymCipherFactory(this, true, {
			{128, MBEDTLS_CIPHER_AES_128_ECB},
			{192, MBEDTLS_CIPHER_AES_192_ECB},
			{256, MBEDTLS_CIPHER_AES_256_ECB}
			})));
		addCipherAlgorithm(&CipherAlgorithm::AesCbcNoPadding, std::unique_ptr<mbedcrypto::MbedcryptoSymCipherFactory>(new mbedcrypto::MbedcryptoSymCipherFactory(this, true, {
			{128, MBEDTLS_CIPHER_AES_128_CBC},
			{192, MBEDTLS_CIPHER_AES_192_CBC},
			{256, MBEDTLS_CIPHER_AES_256_CBC}
			})));
		addCipherAlgorithm(&CipherAlgorithm::AesGcmNoPadding, std::unique_ptr<mbedcrypto::MbedcryptoSymCipherFactory>(new mbedcrypto::MbedcryptoSymCipherFactory(this, true, {
			{128, MBEDTLS_CIPHER_AES_128_GCM},
			{192, MBEDTLS_CIPHER_AES_192_GCM},
			{256, MBEDTLS_CIPHER_AES_256_GCM}
			})));

		addCipherAlgorithm(&CipherAlgorithm::RsaEcbOaepPadding, std::make_unique<mbedcrypto::MbedcryptoAsymCipherFactory>(this, MBEDTLS_PK_RSA, MBEDTLS_RSA_PKCS_V21));

		mbedcrypto::MbedcryptoMessageDigestFactory* sha1Factory = new mbedcrypto::MbedcryptoMessageDigestFactory(this, MBEDTLS_MD_SHA1);
        addMessageDigestAlgorithm(&MessageDigestAlgorithm::SHA_1, std::unique_ptr<mbedcrypto::MbedcryptoMessageDigestFactory>(sha1Factory));
		mbedcrypto::MbedcryptoMessageDigestFactory* sha224Factory = new mbedcrypto::MbedcryptoMessageDigestFactory(this, MBEDTLS_MD_SHA224);
        addMessageDigestAlgorithm(&MessageDigestAlgorithm::SHA_224, std::unique_ptr<mbedcrypto::MbedcryptoMessageDigestFactory>(sha224Factory));
		mbedcrypto::MbedcryptoMessageDigestFactory* sha256Factory = new mbedcrypto::MbedcryptoMessageDigestFactory(this, MBEDTLS_MD_SHA256);
        addMessageDigestAlgorithm(&MessageDigestAlgorithm::SHA_256, std::unique_ptr<mbedcrypto::MbedcryptoMessageDigestFactory>(sha256Factory));
		mbedcrypto::MbedcryptoMessageDigestFactory* sha384Factory = new mbedcrypto::MbedcryptoMessageDigestFactory(this, MBEDTLS_MD_SHA384);
        addMessageDigestAlgorithm(&MessageDigestAlgorithm::SHA_384, std::unique_ptr<mbedcrypto::MbedcryptoMessageDigestFactory>(sha384Factory));
		mbedcrypto::MbedcryptoMessageDigestFactory* sha512Factory = new mbedcrypto::MbedcryptoMessageDigestFactory(this, MBEDTLS_MD_SHA512);
        addMessageDigestAlgorithm(&MessageDigestAlgorithm::SHA_512, std::unique_ptr<mbedcrypto::MbedcryptoMessageDigestFactory>(sha512Factory));

        mbedcrypto::MbedcryptoMacFactory *hmacSha1Factory = new mbedcrypto::MbedcryptoMacFactory(this, MBEDTLS_MD_SHA1);
        addMacAlgorithm(&MacAlgorithm::HmacSHA1, std::unique_ptr<mbedcrypto::MbedcryptoMacFactory>(hmacSha1Factory));
        mbedcrypto::MbedcryptoMacFactory *hmacSha224Factory = new mbedcrypto::MbedcryptoMacFactory(this, MBEDTLS_MD_SHA224);
        addMacAlgorithm(&MacAlgorithm::HmacSHA224, std::unique_ptr<mbedcrypto::MbedcryptoMacFactory>(hmacSha224Factory));
        mbedcrypto::MbedcryptoMacFactory *hmacSha256Factory = new mbedcrypto::MbedcryptoMacFactory(this, MBEDTLS_MD_SHA256);
        addMacAlgorithm(&MacAlgorithm::HmacSHA256, std::unique_ptr<mbedcrypto::MbedcryptoMacFactory>(hmacSha256Factory));
        mbedcrypto::MbedcryptoMacFactory *hmacSha384Factory = new mbedcrypto::MbedcryptoMacFactory(this, MBEDTLS_MD_SHA384);
        addMacAlgorithm(&MacAlgorithm::HmacSHA384, std::unique_ptr<mbedcrypto::MbedcryptoMacFactory>(hmacSha384Factory));
        mbedcrypto::MbedcryptoMacFactory *hmacSha512Factory = new mbedcrypto::MbedcryptoMacFactory(this, MBEDTLS_MD_SHA512);
        addMacAlgorithm(&MacAlgorithm::HmacSHA512, std::unique_ptr<mbedcrypto::MbedcryptoMacFactory>(hmacSha512Factory));

		addKeyAgreementAlgorithm(&KeyAgreementAlgorithm::ECDH, std::make_unique<mbedcrypto::MbedcryptoKaEcdhFactory>(this));

        addSignatureAlgorithm(&SignatureAlgorithm::NONEwithECDSA, std::make_unique<mbedcrypto::MbedcryptoSignFactory>(this, MBEDTLS_PK_ECDSA, MBEDTLS_MD_NONE, nullptr));
        addSignatureAlgorithm(&SignatureAlgorithm::SHA1withECDSA, std::make_unique<mbedcrypto::MbedcryptoSignFactory>(this, MBEDTLS_PK_ECDSA, MBEDTLS_MD_SHA1, sha1Factory));
        addSignatureAlgorithm(&SignatureAlgorithm::SHA224withECDSA, std::make_unique<mbedcrypto::MbedcryptoSignFactory>(this, MBEDTLS_PK_ECDSA, MBEDTLS_MD_SHA224, sha224Factory));
        addSignatureAlgorithm(&SignatureAlgorithm::SHA256withECDSA, std::make_unique<mbedcrypto::MbedcryptoSignFactory>(this, MBEDTLS_PK_ECDSA, MBEDTLS_MD_SHA256, sha256Factory));
        addSignatureAlgorithm(&SignatureAlgorithm::SHA384withECDSA, std::make_unique<mbedcrypto::MbedcryptoSignFactory>(this, MBEDTLS_PK_ECDSA, MBEDTLS_MD_SHA384, sha384Factory));
        addSignatureAlgorithm(&SignatureAlgorithm::SHA512withECDSA, std::make_unique<mbedcrypto::MbedcryptoSignFactory>(this, MBEDTLS_PK_ECDSA, MBEDTLS_MD_SHA512, sha512Factory));

		addSignatureAlgorithm(&SignatureAlgorithm::NONEwithRSA, std::make_unique<mbedcrypto::MbedcryptoSignFactory>(this, MBEDTLS_PK_RSA, MBEDTLS_MD_NONE, nullptr));
		addSignatureAlgorithm(&SignatureAlgorithm::SHA1withECDSA, std::make_unique<mbedcrypto::MbedcryptoSignFactory>(this, MBEDTLS_PK_RSA, MBEDTLS_MD_SHA1, sha1Factory));
		addSignatureAlgorithm(&SignatureAlgorithm::SHA224withECDSA, std::make_unique<mbedcrypto::MbedcryptoSignFactory>(this, MBEDTLS_PK_RSA, MBEDTLS_MD_SHA224, sha224Factory));
		addSignatureAlgorithm(&SignatureAlgorithm::SHA256withECDSA, std::make_unique<mbedcrypto::MbedcryptoSignFactory>(this, MBEDTLS_PK_RSA, MBEDTLS_MD_SHA256, sha256Factory));
		addSignatureAlgorithm(&SignatureAlgorithm::SHA384withECDSA, std::make_unique<mbedcrypto::MbedcryptoSignFactory>(this, MBEDTLS_PK_RSA, MBEDTLS_MD_SHA384, sha384Factory));
		addSignatureAlgorithm(&SignatureAlgorithm::SHA512withECDSA, std::make_unique<mbedcrypto::MbedcryptoSignFactory>(this, MBEDTLS_PK_RSA, MBEDTLS_MD_SHA512, sha512Factory));

        addSecretKeyFactoryAlgorithm(&SecretKeyFactoryAlgorithm::PBKDF2WithHmacSHA1, std::make_unique<soft::SoftPBKDF2SecretKeyFactory>(this, hmacSha1Factory));
        addSecretKeyFactoryAlgorithm(&SecretKeyFactoryAlgorithm::PBKDF2WithHmacSHA224, std::make_unique<soft::SoftPBKDF2SecretKeyFactory>(this, hmacSha224Factory));
        addSecretKeyFactoryAlgorithm(&SecretKeyFactoryAlgorithm::PBKDF2WithHmacSHA256, std::make_unique<soft::SoftPBKDF2SecretKeyFactory>(this, hmacSha256Factory));
        addSecretKeyFactoryAlgorithm(&SecretKeyFactoryAlgorithm::PBKDF2WithHmacSHA384, std::make_unique<soft::SoftPBKDF2SecretKeyFactory>(this, hmacSha384Factory));
        addSecretKeyFactoryAlgorithm(&SecretKeyFactoryAlgorithm::PBKDF2WithHmacSHA512, std::make_unique<soft::SoftPBKDF2SecretKeyFactory>(this, hmacSha512Factory));
        addSecretKeyFactoryAlgorithm(&SecretKeyFactoryAlgorithm::HKDFWithSHA1, std::make_unique<soft::SoftHKDFSecretKeyFactory>(this, hmacSha1Factory));
        addSecretKeyFactoryAlgorithm(&SecretKeyFactoryAlgorithm::HKDFWithSHA224, std::make_unique<soft::SoftHKDFSecretKeyFactory>(this, hmacSha224Factory));
        addSecretKeyFactoryAlgorithm(&SecretKeyFactoryAlgorithm::HKDFWithSHA256, std::make_unique<soft::SoftHKDFSecretKeyFactory>(this, hmacSha256Factory));
        addSecretKeyFactoryAlgorithm(&SecretKeyFactoryAlgorithm::HKDFWithSHA384, std::make_unique<soft::SoftHKDFSecretKeyFactory>(this, hmacSha384Factory));
        addSecretKeyFactoryAlgorithm(&SecretKeyFactoryAlgorithm::HKDFWithSHA512, std::make_unique<soft::SoftHKDFSecretKeyFactory>(this, hmacSha512Factory));

        addKeyFactoryAlgorithm(&KeyFactoryAlgorithm::Pkcs8PrivateKey, std::make_unique<mbedcrypto::MbedcryptoPKCS8KeyFactoryFactory>(this));
        addKeyFactoryAlgorithm(&KeyFactoryAlgorithm::X509PublicKey, std::make_unique<mbedcrypto::MbedcryptoPKCS8KeyFactoryFactory>(this));

        addKeyPairGeneratorAlgorithm(&KeyPairAlgorithm::RSA, std::make_unique<mbedcrypto::MbedcryptoRSAKeyPairGeneratorFactory>(this));
    }

} // namespace jcp
