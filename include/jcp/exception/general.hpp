/**
 * @file	general.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/22
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#ifndef __JCP_EXCEPTION_GENERAL_H__
#define __JCP_EXCEPTION_GENERAL_H__

#include <exception>

namespace jcp {

    namespace exception {

        class GeneralException : public std::exception {
        public:
            GeneralException() : exception() {
            }
            explicit GeneralException(char const *const _Message) : exception(_Message) {
            }
            GeneralException(char const *const _Message, int i) : exception(_Message, i) {
            }
            GeneralException(exception const &_Other) : exception(_Other) {
            }
        };

    }

}

#endif // __JCP_EXCEPTION_GENERAL_H__
