/**
 * @file	asym_key.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#pragma once

#ifndef __JCP_ASYM_KEY_H__
#define __JCP_ASYM_KEY_H__

#define HAS_OPENSSL 1
#define HAS_MBEDCRYPTO 1

#if defined(HAS_OPENSSL) && HAS_OPENSSL
#include <openssl/rsa.h>
#include <openssl/ec.h>
#endif

#if (defined(HAS_MBEDCRYPTO) && HAS_MBEDCRYPTO) || (defined(HAS_MBEDTLS) && HAS_MBEDTLS)
#include <mbedtls/rsa.h>
#include <mbedtls/ecp.h>
#endif

namespace jcp {

    class AsymKey
    {
    public:
        virtual bool isRSAKey() const = 0;
        virtual bool isECKey() const = 0;

        virtual bool setPublicKey(const unsigned char *key, int length) = 0;
        virtual bool setPrivateKey(const unsigned char *key, int length) = 0;
        virtual int getKeySize() const = 0;

    public:
#if defined(HAS_OPENSSL) && HAS_OPENSSL
        virtual unsigned long getOpensslError() const = 0;
        virtual const RSA *getOpensslRSAKey() const = 0;
        virtual const EC_KEY *getOpensslECKey() const = 0;
        virtual void copyFromOpensslRSAKey(const RSA *rsa) = 0;
        virtual void copyFromOpensslECKey(const EC_KEY *ec) = 0;
#endif

#if (defined(HAS_MBEDCRYPTO) && HAS_MBEDCRYPTO) || (defined(HAS_MBEDTLS) && HAS_MBEDTLS)
        virtual unsigned long getMbedtlsError() const = 0;
        virtual const mbedtls_rsa_context *getMbedtlsRSAKey() const = 0;
        virtual const mbedtls_ecp_keypair *getMbedtlsECKey() const = 0;
        virtual void copyFromMbedtlsRSAKey(const mbedtls_rsa_context *rsa) = 0;
        virtual void copyFromMbedtlsECKey(const mbedtls_ecp_keypair *ec) = 0;
#endif
    };

}

#endif // __JCP_ASYM_KEY_H__

