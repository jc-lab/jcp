/**
 * @file	openssl_provider.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/08/14
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#ifndef __JCP_OPENSSL_OPENSSL_PROVIDER_H__
#define __JCP_OPENSSL_OPENSSL_PROVIDER_H__

#include "jcp/provider.hpp"

namespace jcp {

    class OpensslProvider : public Provider {
    public:
        OpensslProvider();

		static void registerTo(Security* security);
    };

} // namespace jcp

#endif // __JCP_OPENSSL_OPENSSL_PROVIDER_H__
