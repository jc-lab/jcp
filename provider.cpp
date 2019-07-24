/**
 * @file	provider.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include "provider.hpp"
#include "cipher_algo.hpp"
#include "message_digest_algo.hpp"
#include "mac_algo.hpp"
#include "key_agreement_algo.hpp"
#include "signature_algo.hpp"
#include "secret_key_factory.hpp"
#include "secret_key_factory_algo.hpp"

namespace jcp {


    void Provider::addCipherAlgorithm(const CipherAlgorithm *algorithm, std::unique_ptr<CipherFactory> factory)
    {
        cipher_algos_.emplace((void*)algorithm, AlgorithmItem<CipherFactory>(algorithm, factory));
    }
    void Provider::addCipherAlgorithm(uint32_t algo_id, const char *name, std::unique_ptr<CipherFactory> factory)
    {
        cipher_algos_.emplace((void*)algo_id, AlgorithmItem<CipherFactory>(algo_id, name, factory));
    }
    void Provider::addMessageDigestAlgorithm(const MessageDigestAlgorithm *algorithm, std::unique_ptr<MessageDigestFactory> factory)
    {
		md_algos_.emplace((void*)algorithm, AlgorithmItem<MessageDigestFactory>(algorithm, factory));
    }
    void Provider::addMessageDigestAlgorithm(uint32_t algo_id, const char *name, std::unique_ptr<MessageDigestFactory> factory)
    {
        md_algos_.emplace((void*)algo_id, AlgorithmItem<MessageDigestFactory>(algo_id, name, factory));
    }
    void Provider::addMacAlgorithm(const MacAlgorithm* algorithm, std::unique_ptr<MacFactory> factory)
    {
        mac_algos_.emplace((void*)algorithm, AlgorithmItem<MacFactory>(algorithm, factory));
    }
    void Provider::addMacAlgorithm(uint32_t algo_id, const char *name, std::unique_ptr<MacFactory> factory)
    {
        mac_algos_.emplace((void*)algo_id, AlgorithmItem<MacFactory>(algo_id, name, factory));
    }
    void Provider::addKeyAgreementAlgorithm(const KeyAgreementAlgorithm* algorithm, std::unique_ptr<KeyAgreementFactory> factory)
    {
        ka_algos_.emplace((void*)algorithm, AlgorithmItem<KeyAgreementFactory>(algorithm, factory));
    }
    void Provider::addKeyAgreementAlgorithm(uint32_t algo_id, const char *name, std::unique_ptr<KeyAgreementFactory> factory)
    {
        ka_algos_.emplace((void*)algo_id, AlgorithmItem<KeyAgreementFactory>(algo_id, name, factory));
    }
    void Provider::addSignatureAlgorithm(const SignatureAlgorithm *algorithm, std::unique_ptr<SignatureFactory> factory)
    {
        sign_algos_.emplace((void*)algorithm, AlgorithmItem<SignatureFactory>(algorithm, factory));
    }
    void Provider::addSignatureAlgorithm(uint32_t algo_id, const char *name, std::unique_ptr<SignatureFactory> factory)
    {
        sign_algos_.emplace((void*)algo_id, AlgorithmItem<SignatureFactory>(algo_id, name, factory));
    }
    void Provider::addSecretKeyFactoryAlgorithm(const SecretKeyFactoryAlgorithm *algorithm, std::unique_ptr<SecretKeyFactory> factory)
    {
        skf_algos_.emplace((void*)algorithm, AlgorithmItem<SecretKeyFactory>(algorithm, factory));
    }
    void Provider::addSecretKeyFactoryAlgorithm(uint32_t algo_id, const char *name, std::unique_ptr<SecretKeyFactory> factory)
    {
        skf_algos_.emplace((void*)algo_id, AlgorithmItem<SecretKeyFactory>(algo_id, name, factory));
    }
    void Provider::setSecureRandomFactory(std::unique_ptr<jcp::SecureRandomFactory> factory)
    {
        secure_random_fac_ = std::move(factory);
    }

    static bool compareText(const char *text1, const char *text2) {
        while(*text1 && *text2) {
            char a = *(text1++);
            char b = *(text2++);
            if((a >= 'A') && (a <= 'Z'))
                a -= ('A' - 'a');
            if((b >= 'A') && (b <= 'Z'))
                b -= ('A' - 'a');
            if(a != b)
                return false;
        }
        if(*text1 || *text2)
            return false;
        return true;
    }

    CipherFactory *Provider::getCipher(uint32_t algo_id) {
		for (std::map<void*, AlgorithmItem<CipherFactory> >::const_iterator iter = cipher_algos_.cbegin(); iter != cipher_algos_.cend(); iter++) {
			if (iter->second.algo_id() == algo_id) {
				return iter->second.factory.get();
			}
		}
		return NULL;
    }

    CipherFactory *Provider::getCipher(const char *name) {
        for(std::map<void*, AlgorithmItem<CipherFactory> >::const_iterator iter = cipher_algos_.cbegin(); iter != cipher_algos_.cend(); iter++) {
            if(compareText(iter->second.name().c_str(), name)) {
                return iter->second.factory.get();
            }
        }
        return NULL;
    }

    MessageDigestFactory *Provider::getMessageDigest(uint32_t algo_id) {
		for (std::map<void*, AlgorithmItem<MessageDigestFactory> >::const_iterator iter = md_algos_.cbegin(); iter != md_algos_.cend(); iter++) {
			if (iter->second.algo_id() == algo_id) {
				return iter->second.factory.get();
			}
		}
		return NULL;
    }

    MessageDigestFactory *Provider::getMessageDigest(const char *name) {
        for(std::map<void*, AlgorithmItem<MessageDigestFactory> >::const_iterator iter = md_algos_.cbegin(); iter != md_algos_.cend(); iter++) {
            if(compareText(iter->second.name().c_str(), name)) {
                return iter->second.factory.get();
            }
        }
        return NULL;
    }

    MacFactory *Provider::getMac(uint32_t algo_id) {
		for (std::map<void*, AlgorithmItem<MacFactory> >::const_iterator iter = mac_algos_.cbegin(); iter != mac_algos_.cend(); iter++) {
			if (iter->second.algo_id() == algo_id) {
				return iter->second.factory.get();
			}
		}
		return NULL;
    }

    MacFactory *Provider::getMac(const char *name) {
        for(std::map<void*, AlgorithmItem<MacFactory> >::const_iterator iter = mac_algos_.cbegin(); iter != mac_algos_.cend(); iter++) {
            if(compareText(iter->second.name().c_str(), name)) {
                return iter->second.factory.get();
            }
        }
        return NULL;
    }

    KeyAgreementFactory *Provider::getKeyAgreement(uint32_t algo_id) {
		for (std::map<void*, AlgorithmItem<KeyAgreementFactory> >::const_iterator iter = ka_algos_.cbegin(); iter != ka_algos_.cend(); iter++) {
			if (iter->second.algo_id() == algo_id) {
				return iter->second.factory.get();
			}
		}
		return NULL;
    }

    KeyAgreementFactory *Provider::getKeyAgreement(const char *name) {
        for(std::map<void*, AlgorithmItem<KeyAgreementFactory> >::const_iterator iter = ka_algos_.cbegin(); iter != ka_algos_.cend(); iter++) {
            if(compareText(iter->second.name().c_str(), name)) {
                return iter->second.factory.get();
            }
        }
        return NULL;
    }

    SignatureFactory *Provider::getSignature(uint32_t algo_id) {
		for (std::map<void*, AlgorithmItem<SignatureFactory> >::const_iterator iter = sign_algos_.cbegin(); iter != sign_algos_.cend(); iter++) {
			if (iter->second.algo_id() == algo_id) {
				return iter->second.factory.get();
			}
		}
		return NULL;
    }

    SignatureFactory *Provider::getSignature(const char *name) {
        for(std::map<void*, AlgorithmItem<SignatureFactory> >::const_iterator iter = sign_algos_.cbegin(); iter != sign_algos_.cend(); iter++) {
            if(compareText(iter->second.name().c_str(), name)) {
                return iter->second.factory.get();
            }
        }
        return NULL;
    }

    SecretKeyFactory *Provider::getSecretKeyFactory(uint32_t algo_id) {
        for (std::map<void*, AlgorithmItem<SecretKeyFactory> >::const_iterator iter = skf_algos_.cbegin(); iter != skf_algos_.cend(); iter++) {
            if (iter->second.algo_id() == algo_id) {
                return iter->second.factory.get();
            }
        }
        return NULL;
    }
    SecretKeyFactory *Provider::getSecretKeyFactory(const char *name) {
        for(std::map<void*, AlgorithmItem<SecretKeyFactory> >::const_iterator iter = skf_algos_.cbegin(); iter != skf_algos_.cend(); iter++) {
            if(compareText(iter->second.name().c_str(), name)) {
                return iter->second.factory.get();
            }
        }
        return NULL;
    }

    SecureRandomFactory* Provider::getSecureRandom() {
        return secure_random_fac_.get();
    }

} // namespace jcp

