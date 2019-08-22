//
// Created by jichan on 2019-08-20.
//

#ifndef __JCP_EC_EC_POINT_HPP__
#define __JCP_EC_EC_POINT_HPP__

#include "../big_integer.hpp"

namespace jcp {
    namespace ec {
        struct ECPoint {
            BigInteger x;
            BigInteger y;
            BigInteger z;
        };
    }
}

#endif // __JCP_EC_EC_POINT_HPP__
