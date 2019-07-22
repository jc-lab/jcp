/**
 * @file	invalid_algo_param.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/20
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#ifndef __JCP_EXCEPTION_INVALID_ALGO_PARAM_H__
#define __JCP_EXCEPTION_INVALID_ALGO_PARAM_H__

#include <exception>

namespace jcp {

    namespace exception {

        class InvalidAlgorithmParameterException : public std::exception {
        public:
            InvalidAlgorithmParameterException() : exception() {
            }
            explicit InvalidAlgorithmParameterException(char const *const _Message) : exception(_Message) {
            }
            InvalidAlgorithmParameterException(char const *const _Message, int i) : exception(_Message, i) {
            }
            InvalidAlgorithmParameterException(exception const &_Other) : exception(_Other) {
            }
        };

    }

}

#endif // __JCP_EXCEPTION_INVALID_ALGO_PARAM_H__
