#include <node.h>
#include <nan.h>

extern "C" {
#include "jhash.h"
#include "jproof.h"
}

class JHashCtx : public Nan::ObjectWrap {
 public:
    static NAN_MODULE_INIT(Init) {
        v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);
        tpl->InstanceTemplate()->SetInternalFieldCount(1);

        Nan::SetPrototypeMethod(tpl, "update", Update);
        Nan::SetPrototypeMethod(tpl, "final", Final);
        Nan::SetPrototypeMethod(tpl, "outputBufferFlush", OutputBufferFlush);

        constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());
        Nan::Set(target, Nan::New("JHashCtx").ToLocalChecked(),
            Nan::GetFunction(tpl).ToLocalChecked());

    }

    static NAN_METHOD(NewInstance) {
        v8::Local<v8::Function> cons = Nan::New(constructor());

        const int argc = info.Length();
        v8::Local<v8::Value> argv[argc];
        for (int i = 0; i < argc; ++i) argv[i] = info[i];

        info.GetReturnValue().Set(Nan::NewInstance(cons, argc, argv).ToLocalChecked());
    }

 private:
    explicit JHashCtx() {
        jhash_init(&ctx_);
    }
    explicit JHashCtx(v8::Local<v8::Object>& output_buffer) : output_buffer_(output_buffer) {
        unsigned char* data = (unsigned char*)node::Buffer::Data(output_buffer);
        size_t len = node::Buffer::Length(output_buffer);
        jhash_init_with_output_buffer(&ctx_, data, len);
    }
    ~JHashCtx() {}

    static NAN_METHOD(New) {

        if (!info.IsConstructCall()) {
            v8::Local<v8::Function> cons = Nan::New(constructor());

            const int argc = info.Length();
            v8::Local<v8::Value> argv[argc];
            for (int i = 0; i < argc; ++i) argv[i] = info[i];

            info.GetReturnValue().Set(Nan::NewInstance(cons, argc, argv).ToLocalChecked());
            return;
        }

        if (info.Length() == 0) {
            JHashCtx* obj = new JHashCtx;
            obj->Wrap(info.This());
            info.GetReturnValue().Set(info.This());
            return;
        }

        v8::Local<v8::Object> output_buffer = info[0].As<v8::Object>();
        if (!node::Buffer::HasInstance(output_buffer)) {
            return Nan::ThrowTypeError("constructor() expects first argument to be of type Buffer.");
        }

        Nan::SetAccessor(info.This(), Nan::New("outputBufferSize").ToLocalChecked(), HandleGetters);

        JHashCtx* obj = new JHashCtx(output_buffer);
        obj->Wrap(info.This());
        info.GetReturnValue().Set(info.This());
    }

    static NAN_METHOD(Update) {
        if (info.Length() < 1) {
            return Nan::ThrowError("update() requires at least one argument of type Buffer");
        }

        v8::Local<v8::Object> buf = info[0].As<v8::Object>();
        if (!node::Buffer::HasInstance(buf)) {
            return Nan::ThrowTypeError("update() requires first argument to be of type Buffer.");
        }

        size_t offset = 0;
        size_t len = node::Buffer::Length(buf);
        if (info.Length() == 2) {
            size_t new_len = info[1]->IsNumber() ? Nan::To<int>(info[1]).FromJust() : len;
            if (len > new_len) {
                len = new_len;
            }
        } else if (info.Length() == 3) {
            size_t new_offset = info[1]->IsNumber() ? Nan::To<int>(info[1]).FromJust() : 0;
            size_t new_len    = info[2]->IsNumber() ? Nan::To<int>(info[2]).FromJust() : len;
            if (new_offset < len) {
                offset = new_offset;
                len   -= offset;
            }
            if (len > new_len) {
                len = new_len;
            }
        }

        const unsigned char* data = (unsigned char *)node::Buffer::Data(buf) + offset;

        JHashCtx* obj = ObjectWrap::Unwrap<JHashCtx>(info.Holder());
        jhash_update(&obj->ctx_, data, len);
    }

    static NAN_METHOD(Final) {
        JHashCtx* obj = ObjectWrap::Unwrap<JHashCtx>(info.Holder());

        JHASH_VALUE value;
        jhash_final(&obj->ctx_, &value);
        char* value_string = jhash_encode(&value);
        info.GetReturnValue().Set(
            Nan::New<v8::String>(value_string).ToLocalChecked());
        jhash_free(value_string);
    }

    static NAN_METHOD(OutputBufferFlush) {
        JHashCtx* obj = ObjectWrap::Unwrap<JHashCtx>(info.Holder());
        obj->ctx_.output_buffer_length = 0;
    }

    static NAN_GETTER(HandleGetters) {
        JHashCtx* obj = ObjectWrap::Unwrap<JHashCtx>(info.Holder());

        std::string propertyName = std::string(*Nan::Utf8String(property));
        if (propertyName == "outputBufferSize") {
            info.GetReturnValue().Set(
                Nan::New((int)obj->ctx_.output_buffer_length));
        } else {
            info.GetReturnValue().Set(Nan::Undefined());
        }
    }

    static inline Nan::Persistent<v8::Function> & constructor() {
        static Nan::Persistent<v8::Function> my_constructor;
        return my_constructor;
    }

    JHASH_CTX ctx_;
    Nan::Persistent<v8::Object> output_buffer_;
};

class JProofVerifyCtx : public Nan::ObjectWrap {
 public:
    static NAN_MODULE_INIT(Init) {
        v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);
        tpl->InstanceTemplate()->SetInternalFieldCount(1);

        Nan::SetPrototypeMethod(tpl, "update", Update);
        Nan::SetPrototypeMethod(tpl, "hasError", HasError);
        Nan::SetPrototypeMethod(tpl, "final", Final);

        constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());
        Nan::Set(target, Nan::New("JProofVerifyCtx").ToLocalChecked(),
            Nan::GetFunction(tpl).ToLocalChecked());

    }

    static NAN_METHOD(NewInstance) {
        v8::Local<v8::Function> cons = Nan::New(constructor());

        const int argc = info.Length();
        v8::Local<v8::Value> argv[argc];
        for (int i = 0; i < argc; ++i) argv[i] = info[i];

        info.GetReturnValue().Set(Nan::NewInstance(cons, argc, argv).ToLocalChecked());
    }

 private:
    explicit JProofVerifyCtx(const char* string) {
        value_.payload = NULL;
        ctx_.program = NULL;
        if (jproof_decode(string, &value_) == JHASH_DECODE_ERR) {
            ctx_.state = 1; // Error state
        } else {
            jproof_verify_init(&ctx_, &value_);
        }
    }
    ~JProofVerifyCtx() {
        jproof_verify_free(&ctx_);
        jproof_value_free(&value_);
    }

    static NAN_METHOD(New) {
        if (!info.IsConstructCall()) {
            v8::Local<v8::Function> cons = Nan::New(constructor());

            const int argc = info.Length();
            v8::Local<v8::Value> argv[argc];
            for (int i = 0; i < argc; ++i) argv[i] = info[i];

            info.GetReturnValue().Set(Nan::NewInstance(cons, argc, argv).ToLocalChecked());
            return;
        }

        if (info.Length() != 1 || !info[0]->IsString()) {
            return Nan::ThrowTypeError("constructor() expects one argument of type string.");
        }

        Nan::Utf8String utf8_string = Nan::Utf8String(info[0]);
        if (utf8_string.length() <= 0) {
            return Nan::ThrowTypeError("constructor() expects one argument of type string.");
        }

        JProofVerifyCtx* obj = new JProofVerifyCtx(*utf8_string);
        obj->Wrap(info.This());
        info.GetReturnValue().Set(info.This());
        return;
    }

    static NAN_METHOD(Update) {
        if (info.Length() < 1) {
            return Nan::ThrowError("update() requires at least one argument of type Buffer");
        }

        v8::Local<v8::Object> buf = info[0].As<v8::Object>();
        if (!node::Buffer::HasInstance(buf)) {
            return Nan::ThrowTypeError("update() requires first argument to be of type Buffer.");
        }

        size_t offset = 0;
        size_t len = node::Buffer::Length(buf);
        if (info.Length() == 2) {
            size_t new_len = info[1]->IsNumber() ? Nan::To<int>(info[1]).FromJust() : len;
            if (len > new_len) {
                len = new_len;
            }
        } else if (info.Length() == 3) {
            size_t new_offset = info[1]->IsNumber() ? Nan::To<int>(info[1]).FromJust() : 0;
            size_t new_len    = info[2]->IsNumber() ? Nan::To<int>(info[2]).FromJust() : len;
            if (new_offset < len) {
                offset = new_offset;
                len   -= offset;
            }
            if (len > new_len) {
                len = new_len;
            }
        }

        const unsigned char* data = (unsigned char *)node::Buffer::Data(buf) + offset;

        JProofVerifyCtx* obj = ObjectWrap::Unwrap<JProofVerifyCtx>(info.Holder());
        jproof_verify_update(&obj->ctx_, data, len);
    }

    static NAN_METHOD(HasError) {
        JProofVerifyCtx* obj = ObjectWrap::Unwrap<JProofVerifyCtx>(info.Holder());

        info.GetReturnValue().Set(
            jproof_verify_check_error(&obj->ctx_) ? Nan::True() : Nan::False());
    }

    static NAN_METHOD(Final) {
        JProofVerifyCtx* obj = ObjectWrap::Unwrap<JProofVerifyCtx>(info.Holder());

        JHASH_VALUE value;
        jproof_verify_final(&obj->ctx_, &value);

        if (jproof_verify_check_error(&obj->ctx_)) {
            info.GetReturnValue().Set(Nan::Null());
            return;
        }

        char* value_string = jhash_encode(&value);
        info.GetReturnValue().Set(
            Nan::New<v8::String>(value_string).ToLocalChecked());
        jhash_free(value_string);
    }

    static inline Nan::Persistent<v8::Function> & constructor() {
        static Nan::Persistent<v8::Function> my_constructor;
        return my_constructor;
    }

    JPROOF_VALUE value_;
    JPROOF_VERIFY_CTX ctx_;
};

class JProofGenerateCtx : public Nan::ObjectWrap {
 public:
    static NAN_MODULE_INIT(Init) {
        v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);
        tpl->InstanceTemplate()->SetInternalFieldCount(1);

        Nan::SetPrototypeMethod(tpl, "getRequest", GetRequest);
        Nan::SetPrototypeMethod(tpl, "generate", Generate);

        constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());
        Nan::Set(target, Nan::New("JProofGenerateCtx").ToLocalChecked(),
            Nan::GetFunction(tpl).ToLocalChecked());

    }

    static NAN_METHOD(NewInstance) {
        v8::Local<v8::Function> cons = Nan::New(constructor());

        const int argc = info.Length();
        v8::Local<v8::Value> argv[argc];
        for (int i = 0; i < argc; ++i) argv[i] = info[i];

        info.GetReturnValue().Set(Nan::NewInstance(cons, argc, argv).ToLocalChecked());
    }

 private:
    explicit JProofGenerateCtx(size_t file_size, size_t range_in_point, size_t range_out_point) {
        jproof_generate_init(&ctx_, file_size, range_in_point, range_out_point);
    }
    ~JProofGenerateCtx() {
        jproof_value_free(&ctx_.value);
    }

    static NAN_METHOD(New) {

        if (!info.IsConstructCall()) {
            v8::Local<v8::Function> cons = Nan::New(constructor());

            const int argc = info.Length();
            v8::Local<v8::Value> argv[argc];
            for (int i = 0; i < argc; ++i) argv[i] = info[i];

            info.GetReturnValue().Set(Nan::NewInstance(cons, argc, argv).ToLocalChecked());
            return;
        }

        if (info.Length() != 3 || !info[0]->IsNumber() || !info[1]->IsNumber() || !info[2]->IsNumber()) {
            return Nan::ThrowTypeError("constructor() expects three integer arguments: file_size, range_in_point, range_out_point.");
        }

        size_t file_size       = (size_t)Nan::To<double>(info[0]).FromJust();
        size_t range_in_point  = (size_t)Nan::To<double>(info[1]).FromJust();
        size_t range_out_point = (size_t)Nan::To<double>(info[2]).FromJust();

        JProofGenerateCtx* obj = new JProofGenerateCtx(file_size, range_in_point, range_out_point);
        obj->Wrap(info.This());
        info.GetReturnValue().Set(info.This());
        return;
    }

    static NAN_METHOD(GetRequest) {

        JProofGenerateCtx* obj = ObjectWrap::Unwrap<JProofGenerateCtx>(info.Holder());

        v8::Local<v8::Object> res = Nan::New<v8::Object>();

        // Head & tail info
        {
            v8::Local<v8::Array> pair = Nan::New<v8::Array>(2);
            Nan::Set(pair, 0, Nan::New((double)(obj->ctx_.request.head_in_point)));
            Nan::Set(pair, 1, Nan::New((double)(obj->ctx_.request.head_size)));
            Nan::Set(res, Nan::New("head").ToLocalChecked(), pair);
        }
        {
            v8::Local<v8::Array> pair = Nan::New<v8::Array>(2);
            Nan::Set(pair, 0, Nan::New((double)(obj->ctx_.request.tail_in_point)));
            Nan::Set(pair, 1, Nan::New((double)(obj->ctx_.request.tail_size)));
            Nan::Set(res, Nan::New("tail").ToLocalChecked(), pair);
        }

        // Hash offsets
        v8::Local<v8::Array> hashes = Nan::New<v8::Array>(obj->ctx_.request.num_hashes);
        for (int i = 0; i < obj->ctx_.request.num_hashes; ++i) {
            v8::Local<v8::Array> pair = Nan::New<v8::Array>(2);
            Nan::Set(pair, 0, Nan::New((double)(obj->ctx_.request.hash_offsets[i])));
            Nan::Set(pair, 1, Nan::New((double)(SHA256_BLOCK_SIZE)));
            Nan::Set(hashes, i, pair);
        }
        Nan::Set(res, Nan::New("hashes").ToLocalChecked(), hashes);

        // Payload size
        Nan::Set(res,
            Nan::New("payloadLength").ToLocalChecked(),
            Nan::New((int)(obj->ctx_.value.payload_length)));

        info.GetReturnValue().Set(res);

    }

    static NAN_METHOD(Generate) {
        JProofGenerateCtx* obj = ObjectWrap::Unwrap<JProofGenerateCtx>(info.Holder());

        if (info.Length() != 1) {
            return Nan::ThrowError("generate() requires one argument of type Buffer.");
        }

        v8::Local<v8::Object> buf = info[0].As<v8::Object>();
        if (!node::Buffer::HasInstance(buf)) {
            return Nan::ThrowTypeError("generate() requires first argument to be of type Buffer.");
        }
        if (node::Buffer::Length(buf) != obj->ctx_.value.payload_length) {
            return Nan::ThrowError("Given Buffer must be exactly the size of the payload.");
        }

        const unsigned char* data = (unsigned char *)node::Buffer::Data(buf);
        memcpy(obj->ctx_.value.payload, data, obj->ctx_.value.payload_length);

        char* value_string = jproof_encode(&obj->ctx_.value);
        info.GetReturnValue().Set(
            Nan::New<v8::String>(value_string).ToLocalChecked());
        jhash_free(value_string);
    }

    static inline Nan::Persistent<v8::Function> & constructor() {
        static Nan::Persistent<v8::Function> my_constructor;
        return my_constructor;
    }

    JPROOF_GENERATE_CTX ctx_;
};

NAN_MODULE_INIT(Init) {
    JHashCtx::Init(target);
    JProofVerifyCtx::Init(target);
    JProofGenerateCtx::Init(target);
    // Nan::Set(target,
    //     Nan::New<v8::String>("jhash").ToLocalChecked(),
    //     Nan::GetFunction(
    //         Nan::New<v8::FunctionTemplate>(JHashCtx::NewInstance)).ToLocalChecked()
    // );
    // Nan::Export(target, "JHashCtx", JHashCtx);
    // Nan::Export(target, "sha256hmac", sha256hmac);
    // Nan::Export(target, "hash256", hash256);
}

NODE_MODULE(jhash, Init)
