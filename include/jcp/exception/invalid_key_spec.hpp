/**
 * @file	invalid_key_spec.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/24
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#ifndef __JCP_EXCEPTION_INVALID_KEY_SPEC_H__
#define __JCP_EXCEPTION_INVALID_KEY_SPEC_H__

#include <exception>

namespace jcp {

    namespace exception {

        class InvalidKeySpecException : public std::exception {
        public:
            InvalidKeySpecException() : exception() {
            }
            explicit InvalidKeySpecException(char const *const _Message) : exception(_Message) {
            }
            InvalidKeySpecException(char const *const _Message, int i) : exception(_Message, i) {
            }
            InvalidKeySpecException(exception const &_Other) : exception(_Other) {
            }
        };

    }

}

#endif // __JCP_EXCEPTION_INVALID_KEY_SPEC_H__
