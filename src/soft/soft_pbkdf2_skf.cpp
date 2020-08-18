/**
 * @file	soft_pbkdf2_skf.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/24
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#include <jcp/soft/soft_pbkdf2_skf.hpp>
#include <jcp/pbe_key_spec.hpp>
#include <jcp/exception/invalid_key_spec.hpp>

namespace jcp {

    namespace soft {

        jcp::Result<SecretKey> SoftPBKDF2SecretKeyFactory::generateSecret(const KeySpec *key_spec) const
        {
            const PBEKeySpec *pbe_key_spec = dynamic_cast<const PBEKeySpec*>(key_spec);
            if(!pbe_key_spec) {
                return jcp::Result<SecretKey>(ResultBuilder<SecretKey, exception::InvalidKeySpecException>().withException().build());
            }

            std::unique_ptr<Mac> prf = mac_factory_->create();
            SecretKey prf_key(pbe_key_spec->getPassword().data(), pbe_key_spec->getPassword().size());
            prf->init(&prf_key);
            int hLen = prf->getMacLength();
            int requestedKeyLen = pbe_key_spec->getKeyLength() / 8;
            int l = (requestedKeyLen > hLen) ? requestedKeyLen : hLen;
            int r = requestedKeyLen - (l - 1) * hLen;
            std::vector<unsigned char> Tbuf(l * hLen);
            int ti_offset = 0;

            std::vector<unsigned char> U_r(hLen);
            std::vector<unsigned char> U_i(pbe_key_spec->getSalt().size() + 4);

            for (int i = 1; i <= l; i++) {
		memset(U_r.data(), 0, U_r.size());
                F(&Tbuf[0], ti_offset, prf.get(), pbe_key_spec, i, &U_r[0], &U_i[0]);
                ti_offset += hLen;
            }

            return ResultBuilder<SecretKey, void>(&Tbuf[0], requestedKeyLen).build();
        }

        void SoftPBKDF2SecretKeyFactory::F(unsigned char *dest, int offset, Mac *prf, const PBEKeySpec *key_spec, int block_index, unsigned char *U_r, unsigned char *U_i) const {
            int hLen = prf->getMacLength();
            const std::vector<unsigned char> &salt = key_spec->getSalt();
            int U_i_len = salt.size() + 4;
            memcpy(U_i, salt.data(), salt.size());
            int_to_bytes(&U_i[salt.size()], block_index);

			std::vector<unsigned char> block(U_i, U_i + U_i_len);

            for (int i = 0; i < key_spec->getIterationCount(); i++) {
                prf->update(block.data(), block.size());
                jcp::Result<Buffer> result_with_digest = prf->doFinal();
				block.clear(); block.insert(block.end(), result_with_digest->data(), result_with_digest->data() + result_with_digest->size());
                bytes_xor(U_r, block.data(), hLen);
            }

            memcpy(&dest[offset], U_r, hLen);
        }

    } // namespace soft

} // namespace jcp

