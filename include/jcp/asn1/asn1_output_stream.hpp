//
// Created by jichan on 2019-08-21.
//

#ifndef __JCP_ASN1_ASN1_OUTPUT_STREAM_HPP__
#define __JCP_ASN1_ASN1_OUTPUT_STREAM_HPP__

namespace jcp {
    namespace asn1 {
        class ASN1OutputStream {
        public:
            virtual int write(unsigned char data) = 0;
            virtual int write(const unsigned char *data, size_t length) {
                int rc = 0;
                while(length--) {
                    rc += write(*(data++));
                }
                return rc;
            }
            virtual int writeLength(int length) {
				int rc = 0;
                if (length > 127) {
                    int size = 1;
                    unsigned int val = length;

                    while ((val >>= 8) != 0)
                        size++;

                    rc += write((unsigned char)(size | 0x80));

                    for (int i = (size - 1) * 8; i >= 0; i -= 8)
                        rc += write((unsigned char)(length >> i));

					return rc;
                }else{
                    return write((unsigned char) length);
                }
            }
        };
    }
}

#endif // __JCP_ASN1_ASN1_OUTPUT_STREAM_HPP__
