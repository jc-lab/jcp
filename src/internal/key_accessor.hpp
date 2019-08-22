//
// Created by jichan on 2019-07-19.
//

#ifndef __JCP_INTERNAL_KEY_ACCESSOR_H__
#define __JCP_INTERNAL_KEY_ACCESSOR_H__

#include <vector>

namespace jcp {

    class SecretKey;

    namespace internal {

        class KeyAccessor {
        public:
            static const std::vector<unsigned char> &getPlainKey(const SecretKey *key);
        };

    }

}


#endif // __JCP_INTERNAL_KEY_ACCESSOR_H__
