/**
 * @file	security.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include <jcp/security.hpp>
#include <jcp/provider.hpp>

namespace jcp {

    Security::StaticInitializer Security::static_initializer_;

    Security::StaticInitializer::StaticInitializer() {
        getInstance();
    }

    Security::Security()
    {
    }

    Security *Security::getInstance() {
        static std::unique_ptr<Security> instance(new Security());
        return instance.get();
    }

    void Security::addProviderImpl(std::shared_ptr<Provider> provider)
    {
        std::unique_lock<std::mutex> lock{mutex_};
        providers_.push_back(provider);
    }

    void Security::addProvider(std::shared_ptr<Provider> provider) {
        getInstance()->addProviderImpl(provider);
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

    SecretKeyFactory* Security::findSecretKeyFactoryImpl(uint32_t algo_id) const {
        SecretKeyFactory* factory = NULL;
        for (std::list< std::shared_ptr<Provider> >::const_iterator iter = providers_.cbegin(); (!factory) && (iter != providers_.cend()); iter++) {
            factory = (*iter)->getSecretKeyFactory(algo_id);
            if(factory)
                break;
        }
        return factory;
    }
    SecretKeyFactory* Security::findSecretKeyFactoryImpl(const char* name) const {
        SecretKeyFactory* factory = NULL;
        for (std::list< std::shared_ptr<Provider> >::const_iterator iter = providers_.cbegin(); (!factory) && (iter != providers_.cend()); iter++) {
            factory = (*iter)->getSecretKeyFactory(name);
            if(factory)
                break;
        }
        return factory;
    }

    KeyFactoryFactory* Security::findKeyFactoryImpl(uint32_t algo_id) const {
        KeyFactoryFactory* factory = NULL;
        for (std::list< std::shared_ptr<Provider> >::const_iterator iter = providers_.cbegin(); (!factory) && (iter != providers_.cend()); iter++) {
            factory = (*iter)->getKeyFactoryFactory(algo_id);
            if(factory)
                break;
        }
        return factory;
    }
    KeyFactoryFactory* Security::findKeyFactoryImpl(const char* name) const {
        KeyFactoryFactory* factory = NULL;
        for (std::list< std::shared_ptr<Provider> >::const_iterator iter = providers_.cbegin(); (!factory) && (iter != providers_.cend()); iter++) {
            factory = (*iter)->getKeyFactoryFactory(name);
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

    KeyUtils *Security::findKeyUtilsImpl() const {
        KeyUtils* factory = NULL;
        for (std::list< std::shared_ptr<Provider> >::const_iterator iter = providers_.cbegin(); (!factory) && (iter != providers_.cend()); iter++) {
            factory = (*iter)->getKeyUtils();
            if(factory)
                break;
        }
        return factory;
    }

	CipherFactory* Security::findCipher(uint32_t algo_id) {
		return getInstance()->findCipherImpl(algo_id);
	}

	CipherFactory* Security::findCipher(const char* name) {
		return getInstance()->findCipherImpl(name);
	}

	MessageDigestFactory* Security::findMessageDigest(uint32_t algo_id) {
		return getInstance()->findMessageDigestImpl(algo_id);
	}

	MessageDigestFactory* Security::findMessageDigest(const char* name) {
		return getInstance()->findMessageDigestImpl(name);
	}

	MacFactory* Security::findMac(uint32_t algo_id) {
		return getInstance()->findMacImpl(algo_id);
	}

	MacFactory* Security::findMac(const char* name) {
		return getInstance()->findMacImpl(name);
	}

	KeyAgreementFactory* Security::findKeyAgreement(uint32_t algo_id) {
		return getInstance()->findKeyAgreementImpl(algo_id);
	}

	KeyAgreementFactory* Security::findKeyAgreement(const char* name) {
		return getInstance()->findKeyAgreementImpl(name);
	}

	SignatureFactory* Security::findSignature(uint32_t algo_id) {
		return getInstance()->findSignatureImpl(algo_id);
	}

	SignatureFactory* Security::findSignature(const char* name) {
		return getInstance()->findSignatureImpl(name);
	}

    SecretKeyFactory* Security::findSecretKeyFactory(uint32_t algo_id) {
        return getInstance()->findSecretKeyFactoryImpl(algo_id);
    }
    SecretKeyFactory* Security::findSecretKeyFactory(const char* name) {
        return getInstance()->findSecretKeyFactoryImpl(name);
    }

    KeyFactoryFactory* Security::findKeyFactory(uint32_t algo_id) {
        return getInstance()->findKeyFactoryImpl(algo_id);
    }
    KeyFactoryFactory* Security::findKeyFactory(const char* name) {
        return getInstance()->findKeyFactoryImpl(name);
    }

    SecureRandomFactory *Security::findSecureRandom() {
        return getInstance()->findSecureRandomImpl();
    }

    const KeyUtils *Security::findKeyUtils() {
        return getInstance()->findKeyUtilsImpl();
    }

} // namespace jcp

