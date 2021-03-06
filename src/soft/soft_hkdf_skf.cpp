/**
 * @file	soft_hkdf_skf.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/08/14
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#include <jcp/soft/soft_hkdf_skf.hpp>
#include <jcp/hkdf_key_spec.hpp>

#include <vector>
#include <jcp/exception/invalid_key_spec.hpp>

namespace jcp {

    namespace soft {

        jcp::Result<SecretKey> SoftHKDFSecretKeyFactory::generateSecret(const KeySpec *key_spec) const
        {
            const HKDFKeySpec *kdf_key_spec = dynamic_cast<const HKDFKeySpec*>(key_spec);
            if(!kdf_key_spec) {
                return jcp::Result<SecretKey>(ResultBuilder<SecretKey, exception::InvalidKeySpecException>().withException().build());
            }

            std::unique_ptr<Mac> hmac = mac_factory_->create();
            std::vector<unsigned char> okm;
            std::vector<unsigned char> prk;
            std::vector<unsigned char> t;
            jcp::Result<Buffer> dr;
            int i;

            const std::vector<unsigned char> &salt = kdf_key_spec->getSalt();
            const std::vector<unsigned char> &info = kdf_key_spec->getInfo();
            if(salt.empty()) {
                std::vector<unsigned char> null_salt(hmac->digest_size());
                SecretKey first_key(null_salt.data(), null_salt.size());
                hmac->init(&first_key);
            }else{
                SecretKey first_key(salt.data(), salt.size());
                hmac->init(&first_key);
            }

            const std::vector<unsigned char> &ikm = kdf_key_spec->getPassword();
            hmac->update(ikm.data(), ikm.size());
            dr = hmac->digest();
            prk.insert(prk.end(), dr->data(), dr->data() + dr->size());

            for(i=0; okm.size() < kdf_key_spec->getKeyLength(); i++) {
                SecretKey second_key(prk.data(), prk.size());
                unsigned char counter = i + 1;
                hmac->init(&second_key);
                if(!t.empty())
                    hmac->update(t.data(), t.size());
                if(info.empty())
                    hmac->update(info.data(), info.size());
                hmac->update(&counter, 1);
                dr = hmac->digest();
				t.clear();
				t.insert(t.end(), dr->data(), dr->data() + dr->size());
                okm.insert(okm.end(), t.begin(), t.end());
            }

			return ResultBuilder<SecretKey, void>(okm.data(), kdf_key_spec->getKeyLength()).build();
        }

    } // namespace soft

} // namespace jcp

