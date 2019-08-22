/**
 * @file	aead_bad_tag.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/23
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#ifndef __JCP_EXCEPTION_AEAD_BAD_TAG_H__
#define __JCP_EXCEPTION_AEAD_BAD_TAG_H__

#include <exception>

namespace jcp {

    namespace exception {

        class AEADBadTagException : public std::exception {
        public:
            AEADBadTagException() : exception() {
            }
            explicit AEADBadTagException(char const *const _Message) : exception(_Message) {
            }
            AEADBadTagException(char const *const _Message, int i) : exception(_Message, i) {
            }
            AEADBadTagException(exception const &_Other) : exception(_Other) {
            }
        };

    }

}

#endif // __JCP_EXCEPTION_AEAD_BAD_TAG_H__
