/**
 * @file	provider.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#ifndef __JCP_PROVIDER_H__
#define __JCP_PROVIDER_H__

#include <memory>
#include <stdint.h>
#include <map>
#include <string>

#include "algo.hpp"

#include "cipher.hpp"
#include "message_digest.hpp"
#include "mac.hpp"
#include "key_agreement.hpp"
#include "signature.hpp"
#include "secret_key_factory.hpp"
#include "secure_random.hpp"

namespace jcp {

    class Security;

    class CipherFactory;
    class MessageDigestFactory;
    class MacFactory;
    class KeyAgreementFactory;
    class SignatureFactory;
    class SecretKeyFactory;
    class SecureRandomFactory;

    class CipherAlgorithm;
    class MessageDigestAlgorithm;
    class MacAlgorithm;
    class KeyAgreementAlgorithm;
    class SignatureAlgorithm;
    class SecretKeyFactoryAlgorithm;

    class Provider {
    private:
        friend class Security;

        template<class T>
        struct AlgorithmItem {
			const Algorithm* algorithm_;
            uint32_t algo_id_;
            std::string name_;
            std::unique_ptr<T> factory;

			AlgorithmItem(const Algorithm* algorithm, std::unique_ptr<T>& _factory)
				: algorithm_(algorithm), factory(std::move(_factory))
			{}

			AlgorithmItem(uint32_t algo_id, const char* name, std::unique_ptr<T>& _factory)
				: algorithm_(NULL), algo_id_(algo_id), name_(name), factory(std::move(_factory))
			{}

			AlgorithmItem(uint32_t algo_id, const std::string & name, std::unique_ptr<T> & _factory)
				: algorithm_(NULL), algo_id_(algo_id), name_(name), factory(std::move(_factory))
			{}

			uint32_t algo_id() const {
				return algorithm_ ? algorithm_->algo_id() : algo_id_;
			}

			const std::string &name() const {
				return algorithm_ ? algorithm_->name() : name_;
			}
        };

        std::map<void*, AlgorithmItem<CipherFactory> > cipher_algos_;
        std::map<void*, AlgorithmItem<MessageDigestFactory> > md_algos_;
        std::map<void*, AlgorithmItem<MacFactory> > mac_algos_;
        std::map<void*, AlgorithmItem<KeyAgreementFactory> > ka_algos_;
        std::map<void*, AlgorithmItem<SignatureFactory> > sign_algos_;
        std::map<void*, AlgorithmItem<SecretKeyFactory> > skf_algos_;
        std::unique_ptr<SecureRandomFactory> secure_random_fac_;

    protected:
        void addCipherAlgorithm(const CipherAlgorithm *algorithm, std::unique_ptr<CipherFactory> factory);
        void addCipherAlgorithm(uint32_t algo_id, const char *name, std::unique_ptr<CipherFactory> factory);
        void addMessageDigestAlgorithm(const MessageDigestAlgorithm *algorithm, std::unique_ptr<MessageDigestFactory> factory);
        void addMessageDigestAlgorithm(uint32_t algo_id, const char *name, std::unique_ptr<MessageDigestFactory> factory);
        void addMacAlgorithm(const MacAlgorithm *algorithm, std::unique_ptr<MacFactory> factory);
        void addMacAlgorithm(uint32_t algo_id, const char *name, std::unique_ptr<MacFactory> factory);
        void addKeyAgreementAlgorithm(const KeyAgreementAlgorithm *algorithm, std::unique_ptr<KeyAgreementFactory> factory);
        void addKeyAgreementAlgorithm(uint32_t algo_id, const char *name, std::unique_ptr<KeyAgreementFactory> factory);
        void addSignatureAlgorithm(const SignatureAlgorithm *algorithm, std::unique_ptr<SignatureFactory> factory);
        void addSignatureAlgorithm(uint32_t algo_id, const char *name, std::unique_ptr<SignatureFactory> factory);
        void addSecretKeyFactoryAlgorithm(const SecretKeyFactoryAlgorithm *algorithm, std::unique_ptr<SecretKeyFactory> factory);
        void addSecretKeyFactoryAlgorithm(uint32_t algo_id, const char *name, std::unique_ptr<SecretKeyFactory> factory);
        void setSecureRandomFactory(std::unique_ptr<SecureRandomFactory> factory);

    public:
        CipherFactory *getCipher(uint32_t algo_id);
        CipherFactory *getCipher(const char *name);
        MessageDigestFactory *getMessageDigest(uint32_t algo_id);
        MessageDigestFactory *getMessageDigest(const char *name);
        MacFactory *getMac(uint32_t algo_id);
        MacFactory *getMac(const char *name);
        KeyAgreementFactory *getKeyAgreement(uint32_t algo_id);
        KeyAgreementFactory *getKeyAgreement(const char *name);
        SignatureFactory *getSignature(uint32_t algo_id);
        SignatureFactory *getSignature(const char *name);
        SecretKeyFactory *getSecretKeyFactory(uint32_t algo_id);
        SecretKeyFactory *getSecretKeyFactory(const char *name);
        SecureRandomFactory *getSecureRandom();
    };

} // namespace jcp

#endif // __JCP_PROVIDER_H__
