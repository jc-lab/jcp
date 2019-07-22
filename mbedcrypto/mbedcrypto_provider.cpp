/**
 * @file	mbedcrypto_provider.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include "mbedcrypto_provider.hpp"
#include "../cipher_algo.hpp"
#include "../message_digest_algo.hpp"
#include "../mac_algo.hpp"
#include "../key_agreement_algo.hpp"
#include "../signature_algo.hpp"

#include "mbedcrypto_securerandom.hpp"
#include "mbedcrypto_cipher_sym.hpp"
#include "mbedcrypto_cipher_asym.hpp"
#include "mbedcrypto_md.hpp"
#include "mbedcrypto_ka_ecdh.hpp"
#include "mbedcrypto_sign.hpp"

#include <mbedtls/cipher.h>

namespace jcp {

    MbedcryptoProvider::MbedcryptoProvider()
    {
		setSecureRandomFactory(std::unique_ptr<SecureRandomFactory>(new mbedcrypto::MbedcryptoSecureRandomFactory()));

		addCipherAlgorithm(&CipherAlgorithm::AesEcbNoPadding, std::unique_ptr<mbedcrypto::MbedcryptoSymCipherFactory>(new mbedcrypto::MbedcryptoSymCipherFactory(true, {
			{128, MBEDTLS_CIPHER_AES_128_ECB},
			{192, MBEDTLS_CIPHER_AES_192_ECB},
			{256, MBEDTLS_CIPHER_AES_256_ECB}
			})));
		addCipherAlgorithm(&CipherAlgorithm::AesCbcNoPadding, std::unique_ptr<mbedcrypto::MbedcryptoSymCipherFactory>(new mbedcrypto::MbedcryptoSymCipherFactory(true, {
			{128, MBEDTLS_CIPHER_AES_128_CBC},
			{192, MBEDTLS_CIPHER_AES_192_CBC},
			{256, MBEDTLS_CIPHER_AES_256_CBC}
			})));
		addCipherAlgorithm(&CipherAlgorithm::AesGcmNoPadding, std::unique_ptr<mbedcrypto::MbedcryptoSymCipherFactory>(new mbedcrypto::MbedcryptoSymCipherFactory(true, {
			{128, MBEDTLS_CIPHER_AES_128_GCM},
			{192, MBEDTLS_CIPHER_AES_192_GCM},
			{256, MBEDTLS_CIPHER_AES_256_GCM}
			})));

		addCipherAlgorithm(&CipherAlgorithm::RsaEcbOaepPadding, std::unique_ptr<mbedcrypto::MbedcryptoAsymCipherFactory>(new mbedcrypto::MbedcryptoAsymCipherFactory(MBEDTLS_PK_RSA, MBEDTLS_RSA_PKCS_V21)));

#if 0
		   MBEDTLS_CIPHER_NONE = 0,             /**< Placeholder to mark the end of cipher-pair lists. */
		MBEDTLS_CIPHER_NULL,                 /**< The identity stream cipher. */
			MBEDTLS_CIPHER_AES_128_ECB,          /**< AES cipher with 128-bit ECB mode. */
			MBEDTLS_CIPHER_AES_192_ECB,          /**< AES cipher with 192-bit ECB mode. */
			MBEDTLS_CIPHER_AES_256_ECB,          /**< AES cipher with 256-bit ECB mode. */
			MBEDTLS_CIPHER_AES_128_CBC,          /**< AES cipher with 128-bit CBC mode. */
			MBEDTLS_CIPHER_AES_192_CBC,          /**< AES cipher with 192-bit CBC mode. */
			MBEDTLS_CIPHER_AES_256_CBC,          /**< AES cipher with 256-bit CBC mode. */
			MBEDTLS_CIPHER_AES_128_CFB128,       /**< AES cipher with 128-bit CFB128 mode. */
			MBEDTLS_CIPHER_AES_192_CFB128,       /**< AES cipher with 192-bit CFB128 mode. */
			MBEDTLS_CIPHER_AES_256_CFB128,       /**< AES cipher with 256-bit CFB128 mode. */
			MBEDTLS_CIPHER_AES_128_CTR,          /**< AES cipher with 128-bit CTR mode. */
			MBEDTLS_CIPHER_AES_192_CTR,          /**< AES cipher with 192-bit CTR mode. */
			MBEDTLS_CIPHER_AES_256_CTR,          /**< AES cipher with 256-bit CTR mode. */
			MBEDTLS_CIPHER_AES_128_GCM,          /**< AES cipher with 128-bit GCM mode. */
			MBEDTLS_CIPHER_AES_192_GCM,          /**< AES cipher with 192-bit GCM mode. */
			MBEDTLS_CIPHER_AES_256_GCM,          /**< AES cipher with 256-bit GCM mode. */
			MBEDTLS_CIPHER_CAMELLIA_128_ECB,     /**< Camellia cipher with 128-bit ECB mode. */
			MBEDTLS_CIPHER_CAMELLIA_192_ECB,     /**< Camellia cipher with 192-bit ECB mode. */
			MBEDTLS_CIPHER_CAMELLIA_256_ECB,     /**< Camellia cipher with 256-bit ECB mode. */
			MBEDTLS_CIPHER_CAMELLIA_128_CBC,     /**< Camellia cipher with 128-bit CBC mode. */
			MBEDTLS_CIPHER_CAMELLIA_192_CBC,     /**< Camellia cipher with 192-bit CBC mode. */
			MBEDTLS_CIPHER_CAMELLIA_256_CBC,     /**< Camellia cipher with 256-bit CBC mode. */
			MBEDTLS_CIPHER_CAMELLIA_128_CFB128,  /**< Camellia cipher with 128-bit CFB128 mode. */
			MBEDTLS_CIPHER_CAMELLIA_192_CFB128,  /**< Camellia cipher with 192-bit CFB128 mode. */
			MBEDTLS_CIPHER_CAMELLIA_256_CFB128,  /**< Camellia cipher with 256-bit CFB128 mode. */
			MBEDTLS_CIPHER_CAMELLIA_128_CTR,     /**< Camellia cipher with 128-bit CTR mode. */
			MBEDTLS_CIPHER_CAMELLIA_192_CTR,     /**< Camellia cipher with 192-bit CTR mode. */
			MBEDTLS_CIPHER_CAMELLIA_256_CTR,     /**< Camellia cipher with 256-bit CTR mode. */
			MBEDTLS_CIPHER_CAMELLIA_128_GCM,     /**< Camellia cipher with 128-bit GCM mode. */
			MBEDTLS_CIPHER_CAMELLIA_192_GCM,     /**< Camellia cipher with 192-bit GCM mode. */
			MBEDTLS_CIPHER_CAMELLIA_256_GCM,     /**< Camellia cipher with 256-bit GCM mode. */
			MBEDTLS_CIPHER_DES_ECB,              /**< DES cipher with ECB mode. */
			MBEDTLS_CIPHER_DES_CBC,              /**< DES cipher with CBC mode. */
			MBEDTLS_CIPHER_DES_EDE_ECB,          /**< DES cipher with EDE ECB mode. */
			MBEDTLS_CIPHER_DES_EDE_CBC,          /**< DES cipher with EDE CBC mode. */
			MBEDTLS_CIPHER_DES_EDE3_ECB,         /**< DES cipher with EDE3 ECB mode. */
			MBEDTLS_CIPHER_DES_EDE3_CBC,         /**< DES cipher with EDE3 CBC mode. */
			MBEDTLS_CIPHER_BLOWFISH_ECB,         /**< Blowfish cipher with ECB mode. */
			MBEDTLS_CIPHER_BLOWFISH_CBC,         /**< Blowfish cipher with CBC mode. */
			MBEDTLS_CIPHER_BLOWFISH_CFB64,       /**< Blowfish cipher with CFB64 mode. */
			MBEDTLS_CIPHER_BLOWFISH_CTR,         /**< Blowfish cipher with CTR mode. */
			MBEDTLS_CIPHER_ARC4_128,             /**< RC4 cipher with 128-bit mode. */
			MBEDTLS_CIPHER_AES_128_CCM,          /**< AES cipher with 128-bit CCM mode. */
			MBEDTLS_CIPHER_AES_192_CCM,          /**< AES cipher with 192-bit CCM mode. */
			MBEDTLS_CIPHER_AES_256_CCM,          /**< AES cipher with 256-bit CCM mode. */
			MBEDTLS_CIPHER_CAMELLIA_128_CCM,     /**< Camellia cipher with 128-bit CCM mode. */
			MBEDTLS_CIPHER_CAMELLIA_192_CCM,     /**< Camellia cipher with 192-bit CCM mode. */
			MBEDTLS_CIPHER_CAMELLIA_256_CCM,     /**< Camellia cipher with 256-bit CCM mode. */
			MBEDTLS_CIPHER_ARIA_128_ECB,         /**< Aria cipher with 128-bit key and ECB mode. */
			MBEDTLS_CIPHER_ARIA_192_ECB,         /**< Aria cipher with 192-bit key and ECB mode. */
			MBEDTLS_CIPHER_ARIA_256_ECB,         /**< Aria cipher with 256-bit key and ECB mode. */
			MBEDTLS_CIPHER_ARIA_128_CBC,         /**< Aria cipher with 128-bit key and CBC mode. */
			MBEDTLS_CIPHER_ARIA_192_CBC,         /**< Aria cipher with 192-bit key and CBC mode. */
			MBEDTLS_CIPHER_ARIA_256_CBC,         /**< Aria cipher with 256-bit key and CBC mode. */
			MBEDTLS_CIPHER_ARIA_128_CFB128,      /**< Aria cipher with 128-bit key and CFB-128 mode. */
			MBEDTLS_CIPHER_ARIA_192_CFB128,      /**< Aria cipher with 192-bit key and CFB-128 mode. */
			MBEDTLS_CIPHER_ARIA_256_CFB128,      /**< Aria cipher with 256-bit key and CFB-128 mode. */
			MBEDTLS_CIPHER_ARIA_128_CTR,         /**< Aria cipher with 128-bit key and CTR mode. */
			MBEDTLS_CIPHER_ARIA_192_CTR,         /**< Aria cipher with 192-bit key and CTR mode. */
			MBEDTLS_CIPHER_ARIA_256_CTR,         /**< Aria cipher with 256-bit key and CTR mode. */
			MBEDTLS_CIPHER_ARIA_128_GCM,         /**< Aria cipher with 128-bit key and GCM mode. */
			MBEDTLS_CIPHER_ARIA_192_GCM,         /**< Aria cipher with 192-bit key and GCM mode. */
			MBEDTLS_CIPHER_ARIA_256_GCM,         /**< Aria cipher with 256-bit key and GCM mode. */
			MBEDTLS_CIPHER_ARIA_128_CCM,         /**< Aria cipher with 128-bit key and CCM mode. */
			MBEDTLS_CIPHER_ARIA_192_CCM,         /**< Aria cipher with 192-bit key and CCM mode. */
			MBEDTLS_CIPHER_ARIA_256_CCM,         /**< Aria cipher with 256-bit key and CCM mode. */
			MBEDTLS_CIPHER_AES_128_OFB,          /**< AES 128-bit cipher in OFB mode. */
			MBEDTLS_CIPHER_AES_192_OFB,          /**< AES 192-bit cipher in OFB mode. */
			MBEDTLS_CIPHER_AES_256_OFB,          /**< AES 256-bit cipher in OFB mode. */
			MBEDTLS_CIPHER_AES_128_XTS,          /**< AES 128-bit cipher in XTS block mode. */
			MBEDTLS_CIPHER_AES_256_XTS,          /**< AES 256-bit cipher in XTS block mode. */
			MBEDTLS_CIPHER_CHACHA20,             /**< ChaCha20 stream cipher. */
			MBEDTLS_CIPHER_CHACHA20_POLY1305,    /**< ChaCha20-Poly1305 AEAD cipher. */
#endif

		mbedcrypto::MbedcryptoMessageDigestFactory* sha1Factory = new mbedcrypto::MbedcryptoMessageDigestFactory(MBEDTLS_MD_SHA1);
        addMessageDigestAlgorithm(&MessageDigestAlgorithm::SHA_1, std::unique_ptr<mbedcrypto::MbedcryptoMessageDigestFactory>(sha1Factory));
		mbedcrypto::MbedcryptoMessageDigestFactory* sha224Factory = new mbedcrypto::MbedcryptoMessageDigestFactory(MBEDTLS_MD_SHA224);
        addMessageDigestAlgorithm(&MessageDigestAlgorithm::SHA_224, std::unique_ptr<mbedcrypto::MbedcryptoMessageDigestFactory>(sha224Factory));
		mbedcrypto::MbedcryptoMessageDigestFactory* sha256Factory = new mbedcrypto::MbedcryptoMessageDigestFactory(MBEDTLS_MD_SHA256);
        addMessageDigestAlgorithm(&MessageDigestAlgorithm::SHA_256, std::unique_ptr<mbedcrypto::MbedcryptoMessageDigestFactory>(sha256Factory));
		mbedcrypto::MbedcryptoMessageDigestFactory* sha384Factory = new mbedcrypto::MbedcryptoMessageDigestFactory(MBEDTLS_MD_SHA384);
        addMessageDigestAlgorithm(&MessageDigestAlgorithm::SHA_384, std::unique_ptr<mbedcrypto::MbedcryptoMessageDigestFactory>(sha384Factory));
		mbedcrypto::MbedcryptoMessageDigestFactory* sha512Factory = new mbedcrypto::MbedcryptoMessageDigestFactory(MBEDTLS_MD_SHA512);
        addMessageDigestAlgorithm(&MessageDigestAlgorithm::SHA_512, std::unique_ptr<mbedcrypto::MbedcryptoMessageDigestFactory>(sha512Factory));

        addMacAlgorithm(&MacAlgorithm::HmacWithSHA1, std::unique_ptr<mbedcrypto::MbedcryptoMacFactory>(new mbedcrypto::MbedcryptoMacFactory(MBEDTLS_MD_SHA1)));
        addMacAlgorithm(&MacAlgorithm::HmacWithSHA224, std::unique_ptr<mbedcrypto::MbedcryptoMacFactory>(new mbedcrypto::MbedcryptoMacFactory(MBEDTLS_MD_SHA224)));
        addMacAlgorithm(&MacAlgorithm::HmacWithSHA256, std::unique_ptr<mbedcrypto::MbedcryptoMacFactory>(new mbedcrypto::MbedcryptoMacFactory(MBEDTLS_MD_SHA256)));
        addMacAlgorithm(&MacAlgorithm::HmacWithSHA384, std::unique_ptr<mbedcrypto::MbedcryptoMacFactory>(new mbedcrypto::MbedcryptoMacFactory(MBEDTLS_MD_SHA384)));
        addMacAlgorithm(&MacAlgorithm::HmacWithSHA512, std::unique_ptr<mbedcrypto::MbedcryptoMacFactory>(new mbedcrypto::MbedcryptoMacFactory(MBEDTLS_MD_SHA512)));

		addKeyAgreementAlgorithm(&KeyAgreementAlgorithm::ECDH, std::unique_ptr<mbedcrypto::MbedcryptoKaEcdhFactory>(new mbedcrypto::MbedcryptoKaEcdhFactory()));

        addSignatureAlgorithm(&SignatureAlgorithm::SHA1withECDSA, std::unique_ptr<mbedcrypto::MbedcryptoSignFactory>(new mbedcrypto::MbedcryptoSignFactory(MBEDTLS_PK_ECDSA, MBEDTLS_MD_SHA1, sha1Factory)));
        addSignatureAlgorithm(&SignatureAlgorithm::SHA224withECDSA, std::unique_ptr<mbedcrypto::MbedcryptoSignFactory>(new mbedcrypto::MbedcryptoSignFactory(MBEDTLS_PK_ECDSA, MBEDTLS_MD_SHA224, sha224Factory)));
        addSignatureAlgorithm(&SignatureAlgorithm::SHA256withECDSA, std::unique_ptr<mbedcrypto::MbedcryptoSignFactory>(new mbedcrypto::MbedcryptoSignFactory(MBEDTLS_PK_ECDSA, MBEDTLS_MD_SHA256, sha256Factory)));
        addSignatureAlgorithm(&SignatureAlgorithm::SHA384withECDSA, std::unique_ptr<mbedcrypto::MbedcryptoSignFactory>(new mbedcrypto::MbedcryptoSignFactory(MBEDTLS_PK_ECDSA, MBEDTLS_MD_SHA384, sha384Factory)));
        addSignatureAlgorithm(&SignatureAlgorithm::SHA512withECDSA, std::unique_ptr<mbedcrypto::MbedcryptoSignFactory>(new mbedcrypto::MbedcryptoSignFactory(MBEDTLS_PK_ECDSA, MBEDTLS_MD_SHA512, sha512Factory)));
    }

} // namespace jcp

