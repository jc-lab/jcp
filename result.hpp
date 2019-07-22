/**
 * @file	result.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef __JCP_RESULT_H__
#define __JCP_RESULT_H__

#include <memory>
#include <vector>

#include "buffer.hpp"

namespace jcp {

    template<typename TResult>
    class Result {
    protected:
        TResult result_;

    public:
        Result() {}

		template<typename... Args>
        Result(Args&&... eargs)
                : result_(eargs...)
        { }

        virtual ~Result() {}

        const TResult &result() const {
            return result_;
        }

        virtual const std::exception* exception() const = 0;
    };

    template <>
    class Result<void> {
    public:
        bool result() const {
            return (exception() == NULL);
        }
        virtual const std::exception* exception() const = 0;
    };

    template <typename TResult, class TException>
    class ResultImpl : public Result<TResult>
    {
    private:
        TException e_;

    public:
        ResultImpl() {}

        ResultImpl(TResult result)
                : Result(result), e_()
        { }

        template<typename... EArgs>
        ResultImpl(TResult result, EArgs&&... eargs)
                : Result(result), e_(std::forward<EArgs>(eargs))
        { }

        const std::exception* exception() const override {
            return &e_;
        }
    };

    template <typename TResult, class TException>
    class ResultImpl< TResult, std::unique_ptr<TException> > : public Result<TResult>
    {
    private:
        std::unique_ptr<TException> e_;

    public:
        ResultImpl(TResult result, std::unique_ptr<TException> e)
                : Result(result), e_(e)
        { }

        const std::exception* exception() const override {
            return e_.get();
        }
    };

    template <typename TResult, class TException>
    class ExceptionResultImpl : public Result<TResult>
    {
    private:
        TException e_;

    public:
        ExceptionResultImpl() {}

        template<typename... EArgs>
        ExceptionResultImpl(EArgs&&... eargs)
                : e_(eargs...)
        { }

        const std::exception* exception() const override {
            return &e_;
        }
    };

    template <typename TResult, class TException>
    class ExceptionResultImpl< TResult, std::unique_ptr<TException> > : public Result<TResult>
    {
    private:
        std::unique_ptr<TException> e_;

    public:
        ExceptionResultImpl(std::unique_ptr<TException> e)
                : e_(e)
        { }

        const std::exception* exception() const override {
            return e_.get();
        }
    };

    template <class TException>
    class ExceptionResultImpl<void, std::unique_ptr<TException> > : public Result<void>
    {
    private:
        std::unique_ptr<TException> e_;

    public:
        ExceptionResultImpl(std::unique_ptr<TException> e)
                : e_(e)
        { }

        const std::exception* exception() const override {
            return e_.get();
        }
    };

    template<typename TResult>
    class NoExceptionResult : public Result<TResult>
    {
    public:
        NoExceptionResult() : Result()
        { }

		template<typename... Args>
		NoExceptionResult(Args&& ... args)
			: Result(args...)
		{ }

        TResult *result() {
            return &result_;
        }

        const std::exception* exception() const override {
            return NULL;
        }
    };

}

#endif // __JCP_RESULT_H__
