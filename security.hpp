/**
 * @file	security.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#ifndef __JCP_SECURITY_H__
#define __JCP_SECURITY_H__

#include <memory>
#include <mutex>
#include <list>
#include "secure_random.hpp"

namespace jcp {

    class Provider;
    class CipherFactory;
    class MessageDigestFactory;
    class MacFactory;
	class KeyAgreementFactory;
	class SignatureFactory;
	class SecureRandomFactory;

    class Security {
    private:
        static Security instance_;

        std::mutex mutex_;
        std::list< std::shared_ptr<Provider> > providers_;

    private:
        Security();

        void addProviderImpl(std::shared_ptr<Provider> provider);

		CipherFactory* findCipherImpl(uint32_t algo_id) const;
		CipherFactory* findCipherImpl(const char* name) const;
		MessageDigestFactory* findMessageDigestImpl(uint32_t algo_id) const;
		MessageDigestFactory* findMessageDigestImpl(const char* name) const;
		MacFactory* findMacImpl(uint32_t algo_id) const;
		MacFactory* findMacImpl(const char* name) const;
		KeyAgreementFactory* findKeyAgreementImpl(uint32_t algo_id) const;
		KeyAgreementFactory* findKeyAgreementImpl(const char* name) const;
		SignatureFactory* findSignatureImpl(uint32_t algo_id) const;
		SignatureFactory* findSignatureImpl(const char* name) const;
        SecureRandomFactory *findSecureRandomImpl() const;

    public:
        static void addProvider(std::shared_ptr<Provider> provider);

        static CipherFactory *findCipher(uint32_t algo_id);
        static CipherFactory *findCipher(const char *name);
        static MessageDigestFactory *findMessageDigest(uint32_t algo_id);
        static MessageDigestFactory *findMessageDigest(const char *name);
		static MacFactory* findMac(uint32_t algo_id);
		static MacFactory* findMac(const char* name);
		static KeyAgreementFactory* findKeyAgreement(uint32_t algo_id);
		static KeyAgreementFactory* findKeyAgreement(const char* name);
		static SignatureFactory* findSignature(uint32_t algo_id);
		static SignatureFactory* findSignature(const char* name);
		static SecureRandomFactory *findSecureRandom();
    };

} // namespace jsecsecurity

#endif // __JCP_SECURITY_H__
