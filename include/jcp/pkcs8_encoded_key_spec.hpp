//
// Created by jichan on 2019-08-21.
//

#ifndef __JCP_PKCS8_ENCODED_KEY_SPEC_HPP__
#define __JCP_PKCS8_ENCODED_KEY_SPEC_HPP__

#include "key_spec.hpp"

#include "result.hpp"
#include "asym_key.hpp"

namespace jcp {
    class PKCS8EncodedKeySpecImpl;
    class PKCS8EncodedKeySpec : public KeySpec {
    private:
        struct ImplDeleter { // default deleter for unique_ptr
            constexpr ImplDeleter() noexcept = default;
            void operator()(PKCS8EncodedKeySpecImpl* _Ptr) const noexcept;
        };

        std::unique_ptr<PKCS8EncodedKeySpecImpl, ImplDeleter> impl_;

        PKCS8EncodedKeySpec(std::unique_ptr<PKCS8EncodedKeySpecImpl, ImplDeleter> &impl);

    public:
        static jcp::Result<std::unique_ptr<PKCS8EncodedKeySpec>> decode(const unsigned char *encoded, size_t length);
        const PKCS8EncodedKeySpecImpl *getImpl() const {
            return impl_.get();
        }
        std::unique_ptr<jcp::AsymKey> generateParsedKey() const;
    };
}

#endif // __JCP_PKCS8_ENCODED_KEY_SPEC_HPP__
