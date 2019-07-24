/**
 * @file	asym_key_impl.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#include "asym_key_impl.hpp"

#include <stdio.h>
#include <stdlib.h>

#if defined(HAS_OPENSSL) && HAS_OPENSSL
#include <openssl/err.h>
#include <openssl/x509.h>
#endif
#if (defined(HAS_MBEDCRYPTO) && HAS_MBEDCRYPTO) || (defined(HAS_MBEDTLS) && HAS_MBEDTLS)
#include <mbedtls/pk.h>
#endif

namespace jcp {

#if defined(HAS_OPENSSL) && HAS_OPENSSL

    void AsymKeyImpl::osslRsaDeleter(RSA *key) {
        RSA_free(key);
    }

    void AsymKeyImpl::osslEcKeyDeleter(EC_KEY *key) {
        EC_KEY_free(key);
    }

#endif

#if (defined(HAS_MBEDCRYPTO) && HAS_MBEDCRYPTO) || (defined(HAS_MBEDTLS) && HAS_MBEDTLS)

    void AsymKeyImpl::mbedRsaDeleter(mbedtls_rsa_context *key) {
        mbedtls_rsa_free(key);
        free(key);
    }

    void AsymKeyImpl::mbedEcKeyDeleter(mbedtls_ecp_keypair *key) {
        mbedtls_ecp_keypair_free(key);
        free(key);
    }

#endif

    void AsymKeyImpl::cleanupKeys() {
#if defined(HAS_OPENSSL) && HAS_OPENSSL
        ossl_rsa_.reset();
        ossl_ec_.reset();
        ossl_err_ = 0;
#endif
#if (defined(HAS_MBEDCRYPTO) && HAS_MBEDCRYPTO) || (defined(HAS_MBEDTLS) && HAS_MBEDTLS)
        mbed_rsa_.reset();
        mbed_ec_.reset();
        mbed_err_ = 0;
#endif
    }

    AsymKeyImpl::AsymKeyImpl()
            : key_type_(KEY_None)
#if defined(HAS_OPENSSL) && HAS_OPENSSL
            ,ossl_rsa_(nullptr, osslRsaDeleter)
            ,ossl_ec_(nullptr, osslEcKeyDeleter)
#endif
#if (defined(HAS_MBEDCRYPTO) && HAS_MBEDCRYPTO) || (defined(HAS_MBEDTLS) && HAS_MBEDTLS)
              ,mbed_rsa_(nullptr, mbedRsaDeleter)
              ,mbed_ec_(nullptr, mbedEcKeyDeleter)
#endif
            {
        cleanupKeys();
    }

    bool AsymKeyImpl::isRSAKey() const {
        return (key_type_ == KEY_RSA_PRIVATE) || (key_type_ == KEY_RSA_PUBLIC);
    }

    bool AsymKeyImpl::isECKey() const {
        return (key_type_ == KEY_EC_PRIVATE) || (key_type_ == KEY_EC_PUBLIC);
    }

    bool AsymKeyImpl::setPublicKey(const unsigned char *key, int length) {
        bool result = true;
#if (defined(HAS_OPENSSL) && HAS_OPENSSL)
        if(!setOpensslPublicKey(key, length))
            result = false;
#endif
#if (defined(HAS_MBEDCRYPTO) && HAS_MBEDCRYPTO) || (defined(HAS_MBEDTLS) && HAS_MBEDTLS)
        if(!setMbedtlsKey(key, length, false))
            result = false;
#endif
        return result;
    }

    bool AsymKeyImpl::setPrivateKey(const unsigned char *key, int length) {
        bool result = true;
#if (defined(HAS_OPENSSL) && HAS_OPENSSL)
		if (!setOpensslPKCS8PrivateKey(key, length))
			result = false;
#endif
#if (defined(HAS_MBEDCRYPTO) && HAS_MBEDCRYPTO) || (defined(HAS_MBEDTLS) && HAS_MBEDTLS)
        if(!setMbedtlsKey(key, length, true))
            result = false;
#endif
        return result;
    }

    int AsymKeyImpl::getKeySize() const {
        int keysize = -1;
#if defined(HAS_OPENSSL) && HAS_OPENSSL
        if (keysize < 0)
            keysize = getOpensslKeySize();
#endif
#if (defined(HAS_MBEDCRYPTO) && HAS_MBEDCRYPTO) || (defined(HAS_MBEDTLS) && HAS_MBEDTLS)
        if (keysize < 0)
            keysize = getMbedtlsKeySize();
#endif
        return keysize;
    }

#if defined(HAS_OPENSSL) && HAS_OPENSSL

    unsigned long AsymKeyImpl::getOpensslError() const {
        return ossl_err_;
    }

    const RSA *AsymKeyImpl::getOpensslRSAKey() const {
        return ossl_rsa_.get();
    }

    const EC_KEY *AsymKeyImpl::getOpensslECKey() const {
        return ossl_ec_.get();
    }

    void AsymKeyImpl::copyFromOpensslRSAKey(const RSA *rsa) {
        KeyType key_type = KEY_RSA_PRIVATE;
        RSA *new_rsa = RSAPrivateKey_dup((RSA *) rsa);
        if (!new_rsa) {
            new_rsa = RSAPublicKey_dup((RSA *) rsa);
            key_type = KEY_RSA_PUBLIC;
        }
        if (new_rsa) {
            ossl_rsa_ = std::unique_ptr<RSA, void (*)(RSA *)>(new_rsa, osslRsaDeleter);
            key_type_ = key_type;
        }
        // TODO: OpenSSL to MbedTLS
    }

    void AsymKeyImpl::copyFromOpensslECKey(const EC_KEY *ec) {
        EC_KEY *new_eckey = EC_KEY_dup(ec);
        if (new_eckey) {
            key_type_ = EC_KEY_get0_private_key(new_eckey) ? KEY_EC_PRIVATE : KEY_EC_PUBLIC;
            ossl_ec_ = std::unique_ptr<EC_KEY, void (*)(EC_KEY *)>(new_eckey, osslEcKeyDeleter);
        }
        // TODO: OpenSSL to MbedTLS
    }
	
	bool AsymKeyImpl::setOpensslPublicKey(const unsigned char* key, int length)
	{
		bool rc = false;
		EVP_PKEY* pkey;
		const unsigned char* q = key;
		pkey = d2i_PUBKEY(NULL, &q, length);
		if (!pkey)
		{
			ossl_err_ = ERR_get_error();
			return false;
		}
		int key_id = EVP_PKEY_base_id(pkey);
		while (key_id && !rc) {
			switch (key_id)
			{
			case EVP_PKEY_RSA:
			{
				RSA* rsa = EVP_PKEY_get1_RSA(pkey);
				copyFromOpensslRSAKey(rsa);
				RSA_free(rsa);
				rc = true;
				key_type_ = KEY_RSA_PUBLIC;
			}
				break;
			case EVP_PKEY_EC:
			{
				EC_KEY* eckey = EVP_PKEY_get1_EC_KEY(pkey);
				copyFromOpensslECKey(eckey);
				EC_KEY_free(eckey);
				rc = true;
				key_type_ = KEY_EC_PUBLIC;
			}
				break;
			}
			key_id = EVP_PKEY_type(key_id);
		}
		EVP_PKEY_free(pkey);
		return rc;
	}

	bool AsymKeyImpl::setOpensslPKCS8PrivateKey(const unsigned char* key, int length)
	{
		bool rc = false;
		const unsigned char* q = key;
		PKCS8_PRIV_KEY_INFO* pkcs8PrivKeyInfo = d2i_PKCS8_PRIV_KEY_INFO(NULL, &q, length);
		if (!pkcs8PrivKeyInfo)
		{
			ossl_err_ = ERR_get_error();
			return false;
		}
		EVP_PKEY* pkey = EVP_PKCS82PKEY(pkcs8PrivKeyInfo);
		int key_id = EVP_PKEY_base_id(pkey);
		while (key_id && !rc) {
			switch (key_id)
			{
			case EVP_PKEY_RSA:
			{
				RSA* rsa = EVP_PKEY_get1_RSA(pkey);
				copyFromOpensslRSAKey(rsa);
				RSA_free(rsa);
				rc = true;
				key_type_ = KEY_RSA_PRIVATE;
			}
			break;
			case EVP_PKEY_EC:
			{
				EC_KEY* eckey = EVP_PKEY_get1_EC_KEY(pkey);
				copyFromOpensslECKey(eckey);
				EC_KEY_free(eckey);
				rc = true;
				key_type_ = KEY_EC_PRIVATE;
			}
			break;
			}
			key_id = EVP_PKEY_type(key_id);
		}
		EVP_PKEY_free(pkey);
		PKCS8_PRIV_KEY_INFO_free(pkcs8PrivKeyInfo);
		return rc;
	}

    int AsymKeyImpl::getOpensslKeySize() const {
        switch(key_type_)
        {
            case KEY_RSA_PRIVATE:
            case KEY_RSA_PUBLIC:
                return RSA_size(ossl_rsa_.get());
            case KEY_EC_PRIVATE:
            case KEY_EC_PUBLIC:
                return -1;
        }
        return -1;
    }

#endif

#if (defined(HAS_MBEDCRYPTO) && HAS_MBEDCRYPTO) || (defined(HAS_MBEDTLS) && HAS_MBEDTLS)

    unsigned long AsymKeyImpl::getMbedtlsError() const {
        return mbed_err_;
    }

    const mbedtls_rsa_context *AsymKeyImpl::getMbedtlsRSAKey() const {
        return mbed_rsa_.get();
    }

    const mbedtls_ecp_keypair *AsymKeyImpl::getMbedtlsECKey() const {
        return mbed_ec_.get();
    }

    void AsymKeyImpl::copyFromMbedtlsRSAKey(const mbedtls_rsa_context *rsa) {
        mbed_rsa_ = std::unique_ptr<mbedtls_rsa_context, void(*)(mbedtls_rsa_context*)>((mbedtls_rsa_context*)malloc(sizeof(mbedtls_rsa_context)), mbedRsaDeleter);
        memset(mbed_rsa_.get(), 0, sizeof(mbedtls_rsa_context));
        mbedtls_rsa_copy(mbed_rsa_.get(), rsa);
    }

    void AsymKeyImpl::copyFromMbedtlsECKey(const mbedtls_ecp_keypair *ec) {
        mbed_ec_ = std::unique_ptr<mbedtls_ecp_keypair, void(*)(mbedtls_ecp_keypair*)>((mbedtls_ecp_keypair*)malloc(sizeof(mbedtls_ecp_keypair)), mbedEcKeyDeleter);
        memset(mbed_ec_.get(), 0, sizeof(mbedtls_ecp_keypair));
        mbedtls_ecp_group_copy(&mbed_ec_.get()->grp, &ec->grp);
        mbedtls_ecp_copy(&mbed_ec_.get()->Q, &ec->Q);
        key_type_ = KEY_EC_PUBLIC;
        if(ec->d.n) {
            mbedtls_mpi_copy(&mbed_ec_.get()->d, &ec->d);
        }
    }

    bool AsymKeyImpl::setMbedtlsKey(const unsigned char *key, int length, bool is_private) {
        bool retval = false;
        int librc;
        mbedtls_pk_context pk_ctx;
        mbedtls_pk_init(&pk_ctx);
        if(is_private)
			librc = mbedtls_pk_parse_key(&pk_ctx, key, length, NULL, 0);
        else
			librc = mbedtls_pk_parse_public_key(&pk_ctx, key, length);
        if (librc != 0)
        {
            goto cleanup;
        }
        switch (mbedtls_pk_get_type(&pk_ctx))
        {
            case MBEDTLS_PK_RSA:
            case MBEDTLS_PK_RSA_ALT:
            case MBEDTLS_PK_RSASSA_PSS:
                copyFromMbedtlsRSAKey(mbedtls_pk_rsa(pk_ctx));
				key_type_ = is_private ? KEY_RSA_PRIVATE : KEY_RSA_PUBLIC;
                retval = true;
                break;
            case MBEDTLS_PK_ECKEY:
            case MBEDTLS_PK_ECKEY_DH:
            case MBEDTLS_PK_ECDSA:
                copyFromMbedtlsECKey(mbedtls_pk_ec(pk_ctx));
				key_type_ = is_private ? KEY_EC_PRIVATE : KEY_EC_PUBLIC;
                retval = true;
                break;
        }

        cleanup:
        mbedtls_pk_free(&pk_ctx);
        return retval;
    }

    int AsymKeyImpl::getMbedtlsKeySize() const {
        switch(key_type_)
        {
            case KEY_RSA_PRIVATE:
            case KEY_RSA_PUBLIC:
                return mbedtls_rsa_get_len(mbed_rsa_.get()) * 8;
            case KEY_EC_PRIVATE:
            case KEY_EC_PUBLIC:
                return mbed_ec_->grp.pbits;
        }
        return -1;
    }

#endif

}
