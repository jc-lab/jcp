/**
 * @file	algo.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/22
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef __JCP_ALGO_H__
#define __JCP_ALGO_H__

#include <string>

namespace jcp {

    class Algorithm {
    public:
        virtual uint32_t algo_id() const = 0;
        virtual const std::string& name() const = 0;
    };

}

#endif // __JCP_ALGO_PARAM_SPEC_H__
