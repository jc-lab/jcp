/**
 * @file	iv_param_spec.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef __JCP_IV_PARAM_SPEC_H__
#define __JCP_IV_PARAM_SPEC_H__

#include <stdint.h>
#include <vector>
#include <memory>
#include "algo_param_spec.hpp"

namespace jcp {

    class IvParameterSpec : public AlgorithmParameterSpec
    {
    private:
        std::vector<uint8_t> iv_;

        IvParameterSpec(const uint8_t *iv, int iv_len)
                : iv_(&iv[0], &iv[iv_len])
        {}

    public:
        /**
         *
         * @param t_len Auth Tag Length (bits)
         * @param iv
         * @param iv_len
         * @return
         */
        static std::unique_ptr<IvParameterSpec> create(const uint8_t *iv, int iv_len) {
            return std::unique_ptr<IvParameterSpec>(new IvParameterSpec(iv, iv_len));
        }

        const std::vector<uint8_t> &get_iv() const {
            return iv_;
        }
    };

}

#endif // __JCP_IV_PARAM_SPEC_H__
