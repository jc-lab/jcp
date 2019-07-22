/**
 * @file	secure_random.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/22
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef __JCP_SECURE_RANDOM_H__
#define __JCP_SECURE_RANDOM_H__

#include <memory>
#include "provider.hpp"
#include "random.hpp"

namespace jcp {

    class SecureRandom : public Random {
    public:
        static std::unique_ptr<SecureRandom> getInstance(Provider *provider = NULL);
    };

    class SecureRandomFactory {
    public:
        virtual std::unique_ptr<SecureRandom> create() = 0;
    };

}

#endif // __JCP_SECURE_RANDOM_H__
