/**
 * @file	asym_key.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef __JCP_ASYM_KEY_H__
#define __JCP_ASYM_KEY_H__

#include "key.hpp"


namespace jcp {

    class AsymKey : public Key {
    public:
        virtual std::unique_ptr<AsymKey> clone() const = 0;
    };

}

#endif // __JCP_ASYM_KEY_H__
