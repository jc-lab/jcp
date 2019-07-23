/**
 * @file	asym_key_impl.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#pragma once

#ifndef __JCP_ASYM_KEY_IMPL_H__
#define __JCP_ASYM_KEY_IMPL_H__

#include <memory>
#include "asym_key.hpp"

namespace jcp {

    class AsymKeyImpl : public AsymKey {
    private:
        enum KeyType {
            KEY_None,
            KEY_RSA_PUBLIC,
            KEY_RSA_PRIVATE,
            KEY_EC_PUBLIC,
            KEY_EC_PRIVATE
        };

        KeyType key_type_;

        void cleanupKeys();

#if defined(HAS_OPENSSL) && HAS_OPENSSL
        unsigned long ossl_err_;
        std::unique_ptr<RSA, void(*)(RSA*)> ossl_rsa_;
        std::unique_ptr<EC_KEY, void(*)(EC_KEY*)> ossl_ec_;

        static void osslRsaDeleter(RSA *key);
        static void osslEcKeyDeleter(EC_KEY *key);
#endif
#if (defined(HAS_MBEDCRYPTO) && HAS_MBEDCRYPTO) || (defined(HAS_MBEDTLS) && HAS_MBEDTLS)
        unsigned long mbed_err_;
        std::unique_ptr<mbedtls_rsa_context, void(*)(mbedtls_rsa_context*)> mbed_rsa_;
        std::unique_ptr<mbedtls_ecp_keypair, void(*)(mbedtls_ecp_keypair*)> mbed_ec_;

        static void mbedRsaDeleter(mbedtls_rsa_context *key);
        static void mbedEcKeyDeleter(mbedtls_ecp_keypair *key);
#endif

    public:
        AsymKeyImpl();
        bool isRSAKey() const override;
        bool isECKey() const override;
        bool setPublicKey(const unsigned char *key, int length) override;
        bool setPrivateKey(const unsigned char *key, int length) override;
        int getKeySize() const override;

#if defined(HAS_OPENSSL) && HAS_OPENSSL
        unsigned long getOpensslError() const override;
        const RSA *getOpensslRSAKey() const override;
        const EC_KEY *getOpensslECKey() const override;
        void copyFromOpensslRSAKey(const RSA *rsa) override;
        void copyFromOpensslECKey(const EC_KEY *ec) override;

		bool setOpensslPublicKey(const unsigned char* key, int length);
		bool setOpensslPKCS8PrivateKey(const unsigned char* key, int length);

        int getOpensslKeySize() const;
#endif

#if (defined(HAS_MBEDCRYPTO) && HAS_MBEDCRYPTO) || (defined(HAS_MBEDTLS) && HAS_MBEDTLS)
        unsigned long getMbedtlsError() const override;
        const mbedtls_rsa_context *getMbedtlsRSAKey() const override;
        const mbedtls_ecp_keypair *getMbedtlsECKey() const override;
        void copyFromMbedtlsRSAKey(const mbedtls_rsa_context *rsa) override;
        void copyFromMbedtlsECKey(const mbedtls_ecp_keypair *ec) override;

        bool setMbedtlsKey(const unsigned char *key, int length, bool is_private);

        int getMbedtlsKeySize() const;
#endif
    };

}

#endif // __JCP_ASYM_KEY_IMPL_H__

