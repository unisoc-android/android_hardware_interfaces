/*
 * Copyright (C) 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#define LOG_TAG "fastboothidl"
#include <android-base/logging.h>
#include <fs_mgr.h>
#include "Fastboot.h"

namespace android {
namespace hardware {
namespace fastboot {
namespace V1_0 {
namespace implementation {

using android::fs_mgr::Fstab;
using android::fs_mgr::ReadDefaultFstab;


/*
* get partition type.
*   0: EXT4
*   1: F2FS
*   2: RAW
*/
FileSystemType _getPartitionType(const char *partitionName)
{
    FileSystemType type = FileSystemType::RAW;
    // from default fstab
    Fstab fstab;
    if (!ReadDefaultFstab(&fstab)) {
        LOG(ERROR) << "[_getPartitionType]Could not read default fstab";
        return type;
    }

    for (const auto& entry : fstab) {
        auto pos = entry.blk_device.find(partitionName);
        if (pos != std::string::npos) {
            if (entry.fs_type == "ext4") {
                type = FileSystemType::EXT4;
            } else if (entry.fs_type == "f2fs") {
                type = FileSystemType::F2FS;
            } else {
                type = FileSystemType::RAW;
            }
            break;
        }
    }

    return type;
}

bool _doOemCommand(const char *oemCmd)
{
    bool ret = true;
    //TODO:do oem command
    LOG(WARNING) << "[doOemCommand]oemCmd:" << oemCmd << ", ret:" << ret;
    return ret;
}


// Methods from ::android::hardware::fastboot::V1_0::IFastboot follow.
Return<void> Fastboot::getPartitionType(const hidl_string& partitionName,
                                        getPartitionType_cb _hidl_cb) {
    FileSystemType fstype = _getPartitionType(partitionName.c_str());
    _hidl_cb(fstype, {Status::SUCCESS, ""});
    return Void();
}

Return<void> Fastboot::doOemCommand(const hidl_string& oemCmd, doOemCommand_cb _hidl_cb) {
    bool ret = _doOemCommand(oemCmd.c_str());
    if (ret) {
        _hidl_cb({Status::SUCCESS, "Oem Command Success"});
    } else {
        _hidl_cb({Status::FAILURE_UNKNOWN, "Command not supported in default implementation"});
    }
    return Void();
}

Return<void> Fastboot::getVariant(getVariant_cb _hidl_cb) {
    hidl_string ret = "Unisoc";
    _hidl_cb(ret, {Status::SUCCESS, ""});
    return Void();
}

Return<void> Fastboot::getOffModeChargeState(getOffModeChargeState_cb _hidl_cb) {
    _hidl_cb(true, {Status::SUCCESS, ""});
    return Void();
}

Return<void> Fastboot::getBatteryVoltageFlashingThreshold(
        getBatteryVoltageFlashingThreshold_cb _hidl_cb) {
    _hidl_cb(4100, {Status::SUCCESS, ""});
    return Void();
}

extern "C" IFastboot* HIDL_FETCH_IFastboot(const char* /* name */) {
    return new Fastboot();
}

}  // namespace implementation
}  // namespace V1_0
}  // namespace fastboot
}  // namespace hardware
}  // namespace android
