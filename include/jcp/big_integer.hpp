//
// Created by jichan on 2019-08-20.
//

#ifndef __JCP_BIG_INTEGER_HPP__
#define __JCP_BIG_INTEGER_HPP__

#include <vector>

namespace jcp {

    class BigInteger {
    private:
        std::vector<unsigned char> buffer_;

    public:
		BigInteger() { }
		BigInteger(const BigInteger& rhs) {
			copyFrom(rhs);
		}
		void operator=(const BigInteger& rhs) {
			copyFrom(rhs);
		}

        virtual void copyFrom(const BigInteger &src);

        /**
         * Read big-endian binary data
         * @param buffer
         * @param length
         */
        virtual void copyFrom(const unsigned char *buffer, size_t length);

        /**
         * Append write big-endian binary data
         * @param buffer
         */
        virtual void copyTo(std::vector<unsigned char>& buffer) const;

		virtual const unsigned char* data(size_t* psize) const;
    };

}

#endif // __JCP_BIG_INTEGER_HPP__
