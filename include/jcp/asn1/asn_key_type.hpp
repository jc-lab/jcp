//
// Created by jichan on 2019-08-20.
//

#ifndef __JCP_ASN1_ASN_KEY_TYPE_HPP__
#define __JCP_ASN1_ASN_KEY_TYPE_HPP__

#include <string>
#include <vector>

namespace jcp {
    namespace asn1 {
        class ASNKeyType {
        private:
            std::string identifier;
            std::vector<unsigned char> body;
        };
    }
}

#endif // __JCP_ASN1_ASN_KEY_TYPE_HPP__
