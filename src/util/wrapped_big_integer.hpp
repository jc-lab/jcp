//
// Created by jichan on 2019-08-21.
//

#ifndef __JCP_SRC_UTIL_WRAPPED_BIG_INTEGER_HPP__
#define __JCP_SRC_UTIL_WRAPPED_BIG_INTEGER_HPP__

#include <jcp/big_integer.hpp>

namespace jcp {
    namespace util {
        class WrappedBigInteger : public BigInteger {
        private:
            const unsigned char *data_;
            const size_t len_;
        public:
            WrappedBigInteger(const unsigned char *data, size_t len) : data_(data), len_(len) {}

            void copyFrom(const BigInteger &src) override {
            }
            void copyFrom(const unsigned char *buffer, size_t length) override {
            }
            void copyTo(std::vector<unsigned char> &buffer) const override {
                buffer.insert(buffer.end(), data_, data_ + len_);
            }
        };
    }
}

#endif // __JCP_SRC_UTIL_WRAPPED_BIG_INTEGER_HPP__
