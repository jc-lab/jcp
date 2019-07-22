/**
 * @file	mbedcrypto_provider.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#ifndef __JCP_MBEDCRYPTO_MBEDCRYPTO_PROVIDER_H__
#define __JCP_MBEDCRYPTO_MBEDCRYPTO_PROVIDER_H__

#include "../provider.hpp"

namespace jcp {

    class MbedcryptoProvider : public Provider {
    public:
        MbedcryptoProvider();
    };

} // namespace jcp

#endif // __JCP_MBEDCRYPTO_MBEDCRYPTO_PROVIDER_H__
