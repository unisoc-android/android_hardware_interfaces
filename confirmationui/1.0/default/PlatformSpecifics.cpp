/*
**
** Copyright 2017, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#include "PlatformSpecifics.h"

#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <time.h>

#include <dlfcn.h>
#include <log/log.h>

namespace android {
namespace hardware {
namespace confirmationui {
namespace V1_0 {
namespace implementation {

#define CONFIRMATIONUI_LIB "libconfirmationui.so"
#define DTWC_DATA_LEN_MAX 512
#define TOKEN_DATA_LEN_MAX 1024

#undef LOG_TAG
#define LOG_TAG "confirmationUI spec"


using ::android::hardware::confirmationui::V1_0::generic::Operation;

void *handle;
typedef int (*proc)(const char*, uint32_t, const uint8_t*, uint32_t,
                      const char*, uint32_t, uint32_t*, uint32_t, uint8_t*, uint32_t*, uint8_t*, uint32_t*);
proc launch = NULL;


MonotonicClockTimeStamper::TimeStamp MonotonicClockTimeStamper::now() {
    timespec ts;
    if (!clock_gettime(CLOCK_BOOTTIME, &ts)) {
        return TimeStamp(ts.tv_sec * UINT64_C(1000) + ts.tv_nsec / UINT64_C(1000000));
    } else {
        return {};
    }
}

support::NullOr<support::hmac_t> HMacImplementation::hmac256(
    const support::auth_token_key_t& key, std::initializer_list<support::ByteBufferProxy> buffers) {
    HMAC_CTX hmacCtx;
    HMAC_CTX_init(&hmacCtx);
    if (!HMAC_Init_ex(&hmacCtx, key.data(), key.size(), EVP_sha256(), nullptr)) {
        return {};
    }
    for (auto& buffer : buffers) {
        if (!HMAC_Update(&hmacCtx, buffer.data(), buffer.size())) {
            return {};
        }
    }
    support::hmac_t result;
    if (!HMAC_Final(&hmacCtx, result.data(), nullptr)) {
        return {};
    }
    return result;
}


struct confirmtionInfo MyOperation::info;

void resetOperationInfo(void)
{
    ALOGD(" %s\n", __func__);
    MyOperation::info.promptlocale.clear();
    MyOperation::info.extraDataBuf.releaseData();
    MyOperation::info.uiOption.releaseData();
    MyOperation::info.dtwc.releaseData();
    MyOperation::info.confirmToken.releaseData();
}

MyOperation::~MyOperation() {
    resetOperationInfo();
}

void* ui_launch_thread(void *arg)
{
    (void)arg;

    uint32_t* uiOps = NULL;
    uint8_t* dtwc_out = NULL;
    uint8_t* token_out = NULL;

    handle = dlopen(CONFIRMATIONUI_LIB, RTLD_LAZY);
    if (!handle) {
        ALOGE("confirmationui lib %s not found.\n", CONFIRMATIONUI_LIB);
    } else {
        launch = (proc)dlsym(handle, "confirmation_launch");
        if(!launch)
        {
            ALOGE("lib symbol 'confirmation_launch' not found. line %d\n", __LINE__);
        }
        else
        {
            uint32_t dtwc_out_len = DTWC_DATA_LEN_MAX;
            dtwc_out = (uint8_t*)malloc(dtwc_out_len);
            if(dtwc_out == NULL) {
                ALOGE("malloc dtwc out failed! line %d\n", __LINE__);
                goto label_out;
            }
            memset(dtwc_out, 0, dtwc_out_len);

            uint32_t token_out_len = TOKEN_DATA_LEN_MAX;
            token_out = (uint8_t*)malloc(token_out_len);
            if(token_out == NULL) {
                ALOGE("malloc confirm token out failed! line %d\n", __LINE__);
                goto label_out;
            }
            memset(token_out, 0, token_out_len);

            uiOps = (uint32_t*)malloc(sizeof(uint32_t) * MyOperation::info.uiOption.size());
            if(uiOps == NULL) {
                ALOGE("malloc confirm ui option data failed! line %d\n", __LINE__);
                goto label_out;
            }
            for(uint32_t i = 0; i < (uint32_t)(MyOperation::info.uiOption.size()); i++) {
                *(uiOps + i) = (uint32_t)MyOperation::info.uiOption[i];
            }

            ALOGD("%s. going to launch ... \n", __func__);
            int ret = (*launch)(MyOperation::info.prompt.c_str(), MyOperation::info.prompt.size(),
                MyOperation::info.extraDataBuf.data(), MyOperation::info.extraDataBuf.size(),
                MyOperation::info.promptlocale.c_str(), MyOperation::info.promptlocale.size(),
                uiOps, MyOperation::info.uiOption.size(),
                dtwc_out, &dtwc_out_len, token_out, &token_out_len);

            ALOGD("%s. after launch ... ret(%d), len_dtwc(%d), len_token(%d)\n", __func__, ret, dtwc_out_len, token_out_len);
            if(static_cast<ResponseCode>(ret) == ResponseCode::OK) {
                MyOperation::info.dtwc.setToExternal(dtwc_out, dtwc_out_len);
                MyOperation::info.confirmToken.setToExternal(token_out, token_out_len);
            }

            MyOperation& op = MyOperation::get();
            ResponseCode rc = op.deliverUserInputEvent(static_cast<ResponseCode>(ret));
            if(rc != ResponseCode::OK) {
                ALOGE("%s. user input handling abnormal ... rc: %d\n", __func__, rc);
            }
        }

    label_out:
        if(uiOps) free(uiOps);
        if(dtwc_out) free(dtwc_out);
        if(token_out) free(token_out);

        dlclose(handle);
    }

    return (void*)0;
}

ResponseCode MyOperation::deliverUserInputEvent(ResponseCode cmd)
{
    ResponseCode rc = ResponseCode::Ignored;
    switch (cmd) {
        case ResponseCode::OK: {
            if (isPending()) {
                ALOGI("deliverUserInputEvent. user OK.\n");
                finalize(info.dtwc, info.confirmToken);
                rc = ResponseCode::OK;
            }
            break;
        }
        case ResponseCode::Canceled: {
            bool ignored = !isPending();
            ALOGI("deliverUserInputEvent. user Cancelled. ignored?%d\n",ignored);
            userCancel();
            finalize(0, 0);
            rc = ignored ? ResponseCode::Ignored : ResponseCode::OK;
            break;
        }
        case ResponseCode::Ignored: {
            ALOGI("deliverUserInputEvent. tui abort.\n");
            abort();
            rc = ResponseCode::Ignored;
            break;
        }
        default:break;
    }

    resetOperationInfo();

    return rc;
}

int MyOperation::confirmationUILaunch()
{
    setPending();
    // do it in separated thread
    pthread_t thread_uiLaunch;
    int rc = pthread_create(&thread_uiLaunch,  NULL,  ui_launch_thread,  NULL);
    if(rc) {
        ALOGE("confirmationui_launch_thread creat failed! abort.\n");
        abort();
        return -1;
    }

    return 0;
}

ResponseCode MyOperation::init(const sp<IConfirmationResultCallback>& resultCB, const hidl_string& promptText,
                      const hidl_vec<uint8_t>& extraData, const hidl_string& locale,
                      const hidl_vec<UIOption>& uiOptions)
{
    ResponseCode result = Operation::init(resultCB, promptText, extraData, locale, uiOptions);
    ALOGE("%s init (rc: %d)\n", __func__, result);
    if (result == ResponseCode::OK) {
        info.prompt = promptText;
        info.promptlocale = locale;
        info.extraDataBuf = extraData;
        info.uiOption = uiOptions;
    }

    return result;
}


}  // namespace implementation
}  // namespace V1_0
}  // namespace confirmationui
}  // namespace hardware
}  // namespace android
