/**
 * @file	security.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include "security.hpp"
#include "provider.hpp"

#if (defined(HAS_MBEDCRYPTO) && HAS_MBEDCRYPTO) || (defined(HAS_MBEDTLS) && HAS_MBEDTLS)
#include "mbedcrypto/mbedcrypto_provider.hpp"
#endif
#if defined(HAS_OPENSSL) && HAS_OPENSSL
#include "openssl/openssl_provider.hpp"
#endif

namespace jcp {

    Security Security::instance_;

    Security::Security()
    {
#if (defined(HAS_MBEDCRYPTO) && HAS_MBEDCRYPTO) || (defined(HAS_MBEDTLS) && HAS_MBEDTLS)
        providers_.push_back(std::shared_ptr<MbedcryptoProvider>(new MbedcryptoProvider()));
#endif
#if defined(HAS_OPENSSL) && HAS_OPENSSL
		providers_.push_back(std::shared_ptr<OpensslProvider>(new OpensslProvider()));
#endif
    }

    void Security::addProviderImpl(std::shared_ptr<Provider> provider)
    {
        std::unique_lock<std::mutex> lock{mutex_};
        providers_.push_back(provider);
    }

    void Security::addProvider(std::shared_ptr<Provider> provider) {
        instance_.addProviderImpl(provider);
    }

    CipherFactory *Security::findCipherImpl(uint32_t algo_id) const {
        CipherFactory *factory = NULL;
        for(std::list< std::shared_ptr<Provider> >::const_iterator iter = providers_.cbegin(); (!factory) && (iter != providers_.cend()); iter++) {
            factory = (*iter)->getCipher(algo_id);
            if(factory)
                break;
        }
        return factory;
    }

    CipherFactory *Security::findCipherImpl(const char *name) const {
        CipherFactory *factory = NULL;
        for(std::list< std::shared_ptr<Provider> >::const_iterator iter = providers_.cbegin(); (!factory) && (iter != providers_.cend()); iter++) {
            factory = (*iter)->getCipher(name);
            if(factory)
                break;
        }
        return factory;
    }

    MessageDigestFactory *Security::findMessageDigestImpl(uint32_t algo_id) const {
        MessageDigestFactory *factory = NULL;
        for(std::list< std::shared_ptr<Provider> >::const_iterator iter = providers_.cbegin(); (!factory) && (iter != providers_.cend()); iter++) {
            factory = (*iter)->getMessageDigest(algo_id);
            if(factory)
                break;
        }
        return factory;
    }

    MessageDigestFactory *Security::findMessageDigestImpl(const char *name) const {
        MessageDigestFactory *factory = NULL;
        for(std::list< std::shared_ptr<Provider> >::const_iterator iter = providers_.cbegin(); (!factory) && (iter != providers_.cend()); iter++) {
            factory = (*iter)->getMessageDigest(name);
            if(factory)
                break;
        }
        return factory;
    }

	MacFactory* Security::findMacImpl(uint32_t algo_id) const {
		MacFactory* factory = NULL;
		for (std::list< std::shared_ptr<Provider> >::const_iterator iter = providers_.cbegin(); (!factory) && (iter != providers_.cend()); iter++) {
			factory = (*iter)->getMac(algo_id);
            if(factory)
                break;
		}
		return factory;
	}

	MacFactory* Security::findMacImpl(const char* name) const {
		MacFactory* factory = NULL;
		for (std::list< std::shared_ptr<Provider> >::const_iterator iter = providers_.cbegin(); (!factory) && (iter != providers_.cend()); iter++) {
			factory = (*iter)->getMac(name);
            if(factory)
                break;
		}
		return factory;
	}

	KeyAgreementFactory* Security::findKeyAgreementImpl(uint32_t algo_id) const {
		KeyAgreementFactory* factory = NULL;
		for (std::list< std::shared_ptr<Provider> >::const_iterator iter = providers_.cbegin(); (!factory) && (iter != providers_.cend()); iter++) {
			factory = (*iter)->getKeyAgreement(algo_id);
		}
		return factory;
	}

	KeyAgreementFactory* Security::findKeyAgreementImpl(const char* name) const {
		KeyAgreementFactory* factory = NULL;
		for (std::list< std::shared_ptr<Provider> >::const_iterator iter = providers_.cbegin(); (!factory) && (iter != providers_.cend()); iter++) {
			factory = (*iter)->getKeyAgreement(name);
            if(factory)
                break;
		}
		return factory;
	}

	SignatureFactory* Security::findSignatureImpl(uint32_t algo_id) const {
		SignatureFactory* factory = NULL;
		for (std::list< std::shared_ptr<Provider> >::const_iterator iter = providers_.cbegin(); (!factory) && (iter != providers_.cend()); iter++) {
			factory = (*iter)->getSignature(algo_id);
            if(factory)
                break;
		}
		return factory;
	}

	SignatureFactory* Security::findSignatureImpl(const char* name) const {
		SignatureFactory* factory = NULL;
		for (std::list< std::shared_ptr<Provider> >::const_iterator iter = providers_.cbegin(); (!factory) && (iter != providers_.cend()); iter++) {
			factory = (*iter)->getSignature(name);
			if(factory)
			    break;
		}
		return factory;
	}

    SecureRandomFactory *Security::findSecureRandomImpl() const {
        SecureRandomFactory* factory = NULL;
        for (std::list< std::shared_ptr<Provider> >::const_iterator iter = providers_.cbegin(); (!factory) && (iter != providers_.cend()); iter++) {
            factory = (*iter)->getSecureRandom();
            if(factory)
                break;
        }
        return factory;
    }

	CipherFactory* Security::findCipher(uint32_t algo_id) {
		return instance_.findCipherImpl(algo_id);
	}

	CipherFactory* Security::findCipher(const char* name) {
		return instance_.findCipherImpl(name);
	}

	MessageDigestFactory* Security::findMessageDigest(uint32_t algo_id) {
		return instance_.findMessageDigestImpl(algo_id);
	}

	MessageDigestFactory* Security::findMessageDigest(const char* name) {
		return instance_.findMessageDigestImpl(name);
	}

	MacFactory* Security::findMac(uint32_t algo_id) {
		return instance_.findMacImpl(algo_id);
	}

	MacFactory* Security::findMac(const char* name) {
		return instance_.findMacImpl(name);
	}

	KeyAgreementFactory* Security::findKeyAgreement(uint32_t algo_id) {
		return instance_.findKeyAgreementImpl(algo_id);
	}

	KeyAgreementFactory* Security::findKeyAgreement(const char* name) {
		return instance_.findKeyAgreementImpl(name);
	}

	SignatureFactory* Security::findSignature(uint32_t algo_id) {
		return instance_.findSignatureImpl(algo_id);
	}

	SignatureFactory* Security::findSignature(const char* name) {
		return instance_.findSignatureImpl(name);
	}

    SecureRandomFactory *Security::findSecureRandom() {
        return instance_.findSecureRandomImpl();
    }

} // namespace jcp

