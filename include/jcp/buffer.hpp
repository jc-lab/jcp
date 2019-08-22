/**
 * @file	buffer.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/20
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef __JCP_BUFFER_H__
#define __JCP_BUFFER_H__

#include <memory>
#include <vector>

#include <assert.h>

namespace jcp {

    class Buffer {
    private:
        Buffer(const Buffer& o) { assert(false); }
        Buffer(Buffer&& o) { assert(false); }

        std::vector<unsigned char> data_;

    public:
        Buffer() {}
        Buffer(size_t size) : data_(size) {}
		Buffer(const std::vector<unsigned char>& src) : data_(src) {}
		Buffer(const unsigned char *src, size_t size) : data_(&src[0], &src[size]) {}
        size_t size() const {
            return data_.size();
        }
        unsigned char *buffer() {
            if(data_.size() <= 0)
                return NULL;
            return &data_[0];
        }
        const unsigned char *data() const {
            return data_.data();
        }
        unsigned char *resize(size_t size) {
            data_.resize(size);
            if(size <= 0)
                return NULL;
            return &data_[0];
        }
    };

}

#endif // __JCP_BUFFER_H__
