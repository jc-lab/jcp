//
// Created by jichan on 2019-08-20.
//

#include <jcp/big_integer.hpp>

namespace jcp {

    void jcp::BigInteger::copyFrom(const jcp::BigInteger &src) {
        buffer_.clear();
		src.copyTo(buffer_);
    }

    void jcp::BigInteger::copyFrom(const unsigned char *buffer, size_t length) {
        buffer_.clear();
        buffer_.insert(buffer_.end(), buffer, buffer + length);
    }

    void jcp::BigInteger::copyTo(std::vector<unsigned char> &buffer) const {
        buffer.insert(buffer.end(), buffer_.begin(), buffer_.end());
    }

	const unsigned char* jcp::BigInteger::data(size_t* psize) const {
		if (psize)
			* psize = buffer_.size();
		return buffer_.data();
	}

}
