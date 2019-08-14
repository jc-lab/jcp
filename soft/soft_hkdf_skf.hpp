/**
 * @file	soft_hkdf_skf.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/08/14
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#ifndef __JCP_SOFT_SOFT_HKDF_SKF_H__
#define __JCP_SOFT_SOFT_HKDF_SKF_H__

#include "../secret_key_factory.hpp"
#include "../mac.hpp"

#include <stdint.h>
#include <memory>

namespace jcp {

    namespace soft {

        class SoftHKDFSecretKeyFactory : public SecretKeyFactory {
        private:
            MacFactory *mac_factory_;

        public:
            SoftHKDFSecretKeyFactory(Provider *provider, MacFactory *mac_factory)
                    : SecretKeyFactory(provider), mac_factory_(mac_factory)
            {
            }

            std::unique_ptr<Result<SecretKey>> generateSecret(const KeySpec *key_spec) const override;
        };

    }

} // namespace jcp

#endif // __JCP_SOFT_SOFT_HKDF_SKF_H__
