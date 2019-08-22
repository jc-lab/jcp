//
// Created by jichan on 2019-08-20.
//

#ifndef __JCP_ASN1_ASN1_OBJECT_IDENTIFIER_HPP__
#define __JCP_ASN1_ASN1_OBJECT_IDENTIFIER_HPP__

#include <string>
#include <vector>

#include "asn1_vector_output_stream.hpp"

namespace jcp {
    namespace asn1 {
        class ASN1ObjectIdentifier {
        protected:
            std::string identifier_;
            std::vector<unsigned char> body_;

        public:
            const std::string &identifier() const {
                return identifier_;
            }
            const std::vector<unsigned char> &body() const {
                return body_;
            }

            bool fromString(const char *identifier) {
                unsigned char temp[5];
                unsigned char oid[32];

                const char *read_ptr = identifier;

                unsigned char *oid_ptr = oid;
                int oid_len = 0;
                int oid_remaining = sizeof(oid);

                unsigned int cur_value = 0;
                int token_count = 0;
                int oid_count = 0;

                while(1) {
                    int i;
                    char c = *read_ptr;
                    if((c >= '0') && (c <= '9')) {
                        cur_value *= 10;
                        cur_value += (c - '0');
                    }else if((c == '.') || (c == 0)) {
                        int n;
                        if(token_count == 0) {
                            if(cur_value > 6)
                                return false;
                            temp[0] = cur_value * 40;
                            n = 0;
                        }else if(token_count == 1) {
                            if(cur_value > 39)
                                return false;
                            temp[0] += cur_value;
                            n = 1;
                        }else{
                            temp[0] = cur_value & 0x7F;
                            cur_value >>= 7;

                            for(n = 1; cur_value; n++) {
                                temp[n] = 0x80 | (cur_value & 0x7F);
                                cur_value >>= 7;
                            }
                        }

                        if(n > oid_remaining)
                            return false;

                        for(i = 0; i < n; i++)
                            oid_ptr[i] = temp[n - i - 1];

                        oid_ptr += n;
                        oid_len += n;
                        oid_remaining -= n;

                        token_count++;

                        cur_value = 0;
                        if(c == 0) {
                            // Null character
                            break;
                        }
                    }

                    read_ptr++;
                }

                identifier_ = identifier;
                body_.clear();
                body_.insert(body_.end(), oid, oid_ptr);

                return true;
            }

            bool fromBody(const unsigned char *oid, int oid_len) {
                char buffer[128];
                char *buffer_ptr = buffer;
                int buffer_remaining = sizeof(buffer) - 1;

                int i;
                uint32_t value;

                if((!oid) || (oid_len <= 0))
                    return false;

                i = snprintf(buffer, sizeof(buffer), "%d.%d", oid[0] / 40, oid[0] % 40);
                buffer_ptr += i;

                //Initialize the value of the sub-identifier
                value = 0;

                //Convert the rest of the OID
                for(i = 1; i < oid_len; i++)
                {
                    //Shift the value to the left
                    value <<= 7;
                    //Update the current value
                    value |= oid[i] & 0x7F;

                    //Bit b8 is set to zero to indicate the last byte
                    if(!(oid[i] & 0x80))
                    {
                        char temp[16];
                        int temp_len = snprintf(temp, sizeof(temp), ".%d", value);

                        if(temp_len <= buffer_remaining)
                        {
                            int i = temp_len;
                            const char *temp_ptr = temp;
                            while((i--) > 0) {
                                *(buffer_ptr++) = *(temp_ptr++);
                            }
                            buffer_remaining -= temp_len;
                        }

                        value = 0;
                    }
                }

                *buffer_ptr = 0;
                body_.insert(body_.end(), oid, oid + oid_len);
                identifier_ = buffer;

                return true;
            }

            std::vector<unsigned char> getEncoded() const {
                ASN1VectorOutputStream output_stream;
                output_stream.write(6);
                output_stream.writeLength(body_.size());
                output_stream.write(body_.data(), body_.size());
                return output_stream.buffer();
            }

        public:
            ASN1ObjectIdentifier() {};
            ASN1ObjectIdentifier(const ASN1ObjectIdentifier& obj) = default;
            ASN1ObjectIdentifier(const char *identifier) {
                fromString(identifier);
            }
            ASN1ObjectIdentifier(const unsigned char *oid, int oid_len) {
                fromBody(oid, oid_len);
            }
            ASN1ObjectIdentifier branch(const char *branch_id) const {
                std::string new_identifier(identifier_);
                new_identifier.append(".");
                new_identifier.append(branch_id);
                return ASN1ObjectIdentifier(new_identifier.c_str());
            }
            bool equals(const ASN1ObjectIdentifier& rhs) const {
                return body_ == rhs.body_;
            }
            bool on(const ASN1ObjectIdentifier& rhs) const {
                return (identifier_.length() > rhs.identifier_.length()) && (identifier_.at(rhs.identifier_.length()) == '.') && (identifier_.compare(0, rhs.identifier_.length(), rhs.identifier_, 0, rhs.identifier_.length()) == 0);
            }

            bool operator==(const ASN1ObjectIdentifier &rhs) const {
                return body_ == rhs.body_;
            }
            bool operator!=(const ASN1ObjectIdentifier &rhs) const {
                return !(rhs == *this);
            }
            bool operator<(const ASN1ObjectIdentifier &rhs) const {
                return body_ < rhs.body_;
            }
            bool operator>(const ASN1ObjectIdentifier &rhs) const {
                return rhs < *this;
            }
            bool operator<=(const ASN1ObjectIdentifier &rhs) const {
                return !(rhs < *this);
            }
            bool operator>=(const ASN1ObjectIdentifier &rhs) const {
                return !(*this < rhs);
            }
        };
    }
}

#endif // __JCP_ASN1_ASN1_OBJECT_IDENTIFIER_HPP__
