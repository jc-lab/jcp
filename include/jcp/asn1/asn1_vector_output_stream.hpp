//
// Created by jichan on 2019-08-21.
//

#ifndef __JCP_ASN1_ASN1_VECTOR_OUTPUT_STREAM_HPP__
#define __JCP_ASN1_ASN1_VECTOR_OUTPUT_STREAM_HPP__

#include "asn1_output_stream.hpp"

namespace jcp {
    namespace asn1 {
        class ASN1VectorOutputStream : public ASN1OutputStream {
        private:
            std::vector<unsigned char> buffer_;

        public:
            virtual int write(unsigned char data) {
                buffer_.push_back(data);
                return 1;
            }

            int write(const unsigned char *data, size_t length) override {
                buffer_.insert(buffer_.end(), data, data + length);
                return length;
            }

            const std::vector<unsigned char> &buffer() const {
                return buffer_;
            }
        };
    }
}

#endif // __JCP_ASN1_ASN1_VECTOR_OUTPUT_STREAM_HPP__
