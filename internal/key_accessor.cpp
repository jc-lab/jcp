//
// Created by jichan on 2019-07-19.
//

#include "key_accessor.hpp"
#include "../secret_key.hpp"

namespace jcp {

    class SecretKey;

    namespace internal {

        const std::vector<unsigned char> &KeyAccessor::getPlainKey(const SecretKey *key) {
            return key->plain_key_;
        }

    }

}
