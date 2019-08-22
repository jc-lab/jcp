/**
 * @file	key.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/08/20
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#pragma once

#ifndef __JCP_KEY_H__
#define __JCP_KEY_H__

#include <string>

#include "result.hpp"

namespace jcp {

    class Key {
    public:
        virtual std::string getAlgorithm() const = 0;
        virtual std::string getFormat() const = 0;
        virtual std::vector<unsigned char> getEncoded() const = 0;
    };

}

#endif // __JCP_KEY_H__

