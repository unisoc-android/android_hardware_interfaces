/*
 * Copyright (C) 2016 The Android Open Source Project
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
#include <assert.h>
#include <dirent.h>
#include <iostream>
#include <fstream>
#include <pthread.h>
#include <regex>
#include <stdio.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <cutils/uevent.h>
#include <sys/epoll.h>
#include <utils/Errors.h>
#include <utils/StrongPointer.h>

#include "Usb.h"

namespace android {
namespace hardware {
namespace usb {
namespace V1_1 {
namespace implementation {

// Set by the signal handler to destroy the thread
volatile bool destroyThread;

#define	DUAL_ROLE_USB_PATH	"/sys/class/dual_role_usb/"
#define	TYPEC_PATH		"/sys/class/typec/"
const char *class_typec;

// Protects *usb assignment
Usb *usb;

Usb::Usb() {
    pthread_mutex_lock(&mLock);
    // Make this a singleton class
    assert(usb == NULL);
    usb = this;
    pthread_mutex_unlock(&mLock);
}

int32_t readFile(std::string filename, std::string& contents) {
    std::ifstream file(filename);

    if (file.is_open()) {
        getline(file, contents);
        file.close();
        return 0;
    }
    return -1;
}

std::string appendRoleNodeHelper(const std::string portName, PortRoleType type) {
    std::string node(class_typec + portName);

    switch(type) {
        case PortRoleType::DATA_ROLE:
            return node + "/data_role";
        case PortRoleType::POWER_ROLE:
            return node + "/power_role";
        default:
            return node + "/mode";
    }
}

std::string convertRoletoString(PortRole role) {
    if (role.type == PortRoleType::POWER_ROLE) {
        if (role.role == static_cast<uint32_t> (PortPowerRole::SOURCE))
            return "source";
        else if (role.role ==  static_cast<uint32_t> (PortPowerRole::SINK))
            return "sink";
    } else if (role.type == PortRoleType::DATA_ROLE) {
        if (role.role == static_cast<uint32_t> (PortDataRole::HOST))
            return "host";
        if (role.role == static_cast<uint32_t> (PortDataRole::DEVICE))
            return "device";
    } else if (role.type == PortRoleType::MODE) {
        if (role.role == static_cast<uint32_t> ( V1_0::PortMode::UFP))
            return "ufp";
        if (role.role == static_cast<uint32_t> ( V1_0::PortMode::DFP))
            return "dfp";
    }
    return "none";
}

Return<void> Usb::switchRole(const hidl_string& portName,
        const PortRole& newRole) {
    std::string filename = appendRoleNodeHelper(std::string(portName.c_str()),
        newRole.type);
    std::ofstream file(filename);
    std::string written;

    ALOGI("filename write: %s role:%d", filename.c_str(), newRole.role);

    if (file.is_open()) {
        file << convertRoletoString(newRole).c_str();
        file.close();
        if (!readFile(filename, written)) {
            ALOGI("written: %s", written.c_str());
            if (written == convertRoletoString(newRole)) {
                ALOGI("Role switch successfull");
                Return<void> ret =
                    mCallback_1_0->notifyRoleSwitchStatus(portName, newRole,
                    Status::SUCCESS);
                if (!ret.isOk())
                    ALOGE("RoleSwitchStatus error %s",
                        ret.description().c_str());
            }
        }
    }

    Return<void> ret = mCallback_1_0->notifyRoleSwitchStatus(portName, newRole, Status::ERROR);
    if (!ret.isOk())
        ALOGE("RoleSwitchStatus error %s", ret.description().c_str());

    return Void();
}

Status getAccessoryConnected(const std::string &portName, std::string accessory) {
  std::string filename;
  std::string port0_partner = "port0-partner";
  DIR *dp;

  dp = opendir(TYPEC_PATH);
  if (dp != NULL)
    filename = class_typec + portName + "/supported_accessory_modes";
  else
    filename = class_typec + portName + "/accessory_mode";

  closedir(dp);
  if (readFile(filename, accessory)) {
    ALOGE("getAccessoryConnected: Failed to open filesystem node: %s",
          filename.c_str());
    return Status::ERROR;
  }
  return Status::SUCCESS;
}

Status getCurrentRoleHelper(std::string portName,
        PortRoleType type, uint32_t &currentRole)  {
    std::string filename;
    std::string roleName;
    std::string accessory;

    if (type == PortRoleType::POWER_ROLE) {
        filename = class_typec + portName + "/power_role";
        currentRole = static_cast<uint32_t>(PortPowerRole::NONE);
    } else if (type == PortRoleType::DATA_ROLE) {
        filename = class_typec + portName + "/data_role";
        currentRole = static_cast<uint32_t> (PortDataRole::NONE);
    } else if (type == PortRoleType::MODE) {
        filename = class_typec + portName + "/mode";
        currentRole = static_cast<uint32_t> ( V1_0::PortMode::NONE);
    } else {
        return Status::ERROR;
    }

    if (type == PortRoleType::MODE) {
        if (getAccessoryConnected(portName, accessory) != Status::SUCCESS) {
            return Status::ERROR;
        }
        if (accessory == "analog_audio") {
            currentRole = static_cast<uint32_t>(PortMode_1_1::AUDIO_ACCESSORY);
            return Status::SUCCESS;
        } else if (accessory == "debug") {
            currentRole = static_cast<uint32_t>(PortMode_1_1::DEBUG_ACCESSORY);
            return Status::SUCCESS;
        }
    }

    if (readFile(filename, roleName)) {
        ALOGE("getCurrentRole: Failed to open filesystem node");
        return Status::ERROR;
    }

    if (roleName == "dfp")
        currentRole = static_cast<uint32_t> ( V1_0::PortMode::DFP);
    else if (roleName == "ufp" || roleName == "0")
        currentRole = static_cast<uint32_t> ( V1_0::PortMode::UFP);
    else if (roleName == "source" || roleName == "[source] sink" || roleName == "[source]")
        currentRole = static_cast<uint32_t> (PortPowerRole::SOURCE);
    else if (roleName == "sink" || roleName == "source [sink]" || roleName == "[sink]")
        currentRole = static_cast<uint32_t> (PortPowerRole::SINK);
    else if (roleName == "host" || roleName == "[host] device" || roleName == "[host]")
        currentRole = static_cast<uint32_t> (PortDataRole::HOST);
    else if (roleName == "device" || roleName == "host [device]" || roleName == "[device]")
        currentRole = static_cast<uint32_t> (PortDataRole::DEVICE);
    else if (roleName != "none") {
         /* case for none has already been addressed.
          * so we check if the role isnt none.
          */
        return Status::UNRECOGNIZED_ROLE;
    }
    return Status::SUCCESS;
}

Status getTypeCPortNamesHelper(std::vector<std::string>& names) {
    DIR *dp;

    dp = opendir(class_typec);
    if (dp != NULL)
    {
rescan:
        int32_t ports = 0;
        int32_t current = 0;
        struct dirent *ep;

        while ((ep = readdir (dp))) {
            if (ep->d_type == DT_LNK) {
                ports++;
            }
        }

        if (ports == 0) {
            closedir(dp);
            return Status::SUCCESS;
        }

        names.resize(ports);
        rewinddir(dp);

        while ((ep = readdir (dp))) {
            if (ep->d_type == DT_LNK) {
                /* Check to see if new ports were added since the first pass. */
                if (current >= ports) {
                    rewinddir(dp);
                    goto rescan;
                }
                names[current++] = ep->d_name;
            }
        }

        closedir(dp);
        return Status::SUCCESS;
    }

    ALOGE("Failed to open %s", class_typec);
    return Status::ERROR;
}

bool canSwitchRoleHelper(const std::string portName, PortRoleType type)  {
    std::string filename = appendRoleNodeHelper(portName, type);
    std::ofstream file(filename);

    if (file.is_open()) {
        file.close();
        return true;
    }
    return false;
}

Status getPortStatusHelper (hidl_vec<PortStatus_1_1> *currentPortStatus_1_1,
    bool V1_0) {
    std::vector<std::string> names;
    Status result = getTypeCPortNamesHelper(names);
    DIR *dp;

    if (result == Status::SUCCESS) {
        currentPortStatus_1_1->resize(names.size());
        for(std::vector<std::string>::size_type i = 0; i < names.size(); i++) {
            ALOGI("%s", names[i].c_str());
            (*currentPortStatus_1_1)[i].status.portName = names[i];

	    dp = opendir(TYPEC_PATH);
	    if (dp != NULL) {
		if (names[i] == "port0")
			(*currentPortStatus_1_1)[i].status.portName = names[i];
		else {
			(*currentPortStatus_1_1)[i].status.portName = "port0";
			names[i] = "port0";
		}
		closedir(dp);
	    }

            uint32_t currentRole;
            if (getCurrentRoleHelper(names[i],
                    PortRoleType::POWER_ROLE,
                    currentRole) == Status::SUCCESS) {
                (*currentPortStatus_1_1)[i].status.currentPowerRole =
                static_cast<PortPowerRole> (currentRole);
            } else {
                ALOGE("Error while retreiving portNames");
                goto done;
            }

            if (getCurrentRoleHelper(names[i],
                    PortRoleType::DATA_ROLE,
                    currentRole) == Status::SUCCESS) {
                (*currentPortStatus_1_1)[i].status.currentDataRole =
                        static_cast<PortDataRole> (currentRole);
            } else {
                ALOGE("Error while retreiving current port role");
                goto done;
            }

            if (getCurrentRoleHelper(names[i],
                    PortRoleType::MODE,
                    currentRole) == Status::SUCCESS) {
                (*currentPortStatus_1_1)[i].currentMode =
                    static_cast<PortMode_1_1> (currentRole);
                (*currentPortStatus_1_1)[i].status.currentMode =
                    static_cast<V1_0::PortMode>(currentRole);
            } else {
                ALOGE("Error while retreiving current data role");
                goto done;
            }

            (*currentPortStatus_1_1)[i].status.canChangeMode =
                canSwitchRoleHelper(names[i], PortRoleType::MODE);;
            (*currentPortStatus_1_1)[i].status.canChangeDataRole =
                canSwitchRoleHelper(names[i], PortRoleType::DATA_ROLE);
            (*currentPortStatus_1_1)[i].status.canChangePowerRole =
                canSwitchRoleHelper(names[i], PortRoleType::POWER_ROLE);

            ALOGI("canChangeMode:%d canChagedata:%d canChangePower:%d",
                (*currentPortStatus_1_1)[i].status.canChangeMode,
                (*currentPortStatus_1_1)[i].status.canChangeDataRole,
                (*currentPortStatus_1_1)[i].status.canChangePowerRole);
            if (V1_0) {
                (*currentPortStatus_1_1)[i].status.supportedModes = V1_0::PortMode::DFP;
            } else {
                (*currentPortStatus_1_1)[i].supportedModes = PortMode_1_1::UFP | PortMode_1_1::DFP;
                (*currentPortStatus_1_1)[i].status.supportedModes = V1_0::PortMode::NONE;
                (*currentPortStatus_1_1)[i].status.currentMode = V1_0::PortMode::NONE;
            }
        }
        return Status::SUCCESS;
    }
done:
    return Status::ERROR;
}

Return<void> Usb::queryPortStatus() {
    hidl_vec<PortStatus_1_1> currentPortStatus_1_1;
    hidl_vec<V1_0::PortStatus> currentPortStatus;
    Status status;
    sp<IUsbCallback> callback_V1_1 = IUsbCallback::castFrom(mCallback_1_0);
    pthread_mutex_lock(&mLock);

    if (mCallback_1_0 != NULL) {
        if (callback_V1_1 != NULL) {
            status = getPortStatusHelper(&currentPortStatus_1_1, false);
        } else {
            status = getPortStatusHelper(&currentPortStatus_1_1, true);
            currentPortStatus.resize(currentPortStatus_1_1.size());
            for (unsigned long i = 0; i < currentPortStatus_1_1.size(); i++)
                currentPortStatus[i] = currentPortStatus_1_1[i].status;
        }

        Return<void> ret;
        if (callback_V1_1 != NULL)
            ret = callback_V1_1->notifyPortStatusChange_1_1(currentPortStatus_1_1, status);
        else
            ret = mCallback_1_0->notifyPortStatusChange(currentPortStatus, status);
        if (!ret.isOk())
            ALOGE("queryPortStatus error %s", ret.description().c_str());
    } else {
        ALOGI("Notifying userspace skipped. Callback is NULL");
    }
    pthread_mutex_unlock(&mLock);

    return Void();
}
struct data {
    int uevent_fd;
    android::hardware::usb::V1_1::implementation::Usb *usb;
};

static void uevent_event(uint32_t /*epevents*/, struct data *payload) {
    char msg[UEVENT_MSG_LEN + 2];
    char *cp;
    int n;

    n = uevent_kernel_multicast_recv(payload->uevent_fd, msg, UEVENT_MSG_LEN);
    if (n <= 0)
        return;
    if (n >= UEVENT_MSG_LEN)   /* overflow -- discard */
        return;

    msg[n] = '\0';
    msg[n + 1] = '\0';
    cp = msg;

    while (*cp) {
        if (std::regex_match(cp, std::regex("(add)(.*)(-partner)"))) {
            ALOGI("partner added");
            pthread_mutex_lock(&payload->usb->mPartnerLock);
            payload->usb->mPartnerUp = true;
            pthread_cond_signal(&payload->usb->mPartnerCV);
            pthread_mutex_unlock(&payload->usb->mPartnerLock);
        } else if (!strncmp(cp, "DEVTYPE=typec_", strlen("DEVTYPE=typec_"))) {
            hidl_vec<PortStatus_1_1> currentPortStatus_1_1;
            ALOGI("uevent received %s", cp);
            pthread_mutex_lock(&payload->usb->mLock);
            if (payload->usb->mCallback_1_0 != NULL) {
                sp<IUsbCallback> callback_V1_1 = IUsbCallback::castFrom(payload->usb->mCallback_1_0);
                Return<void> ret;
                // V1_1 callback
                if (callback_V1_1 != NULL) {
                    Status status = getPortStatusHelper(&currentPortStatus_1_1, false);
                    ret = callback_V1_1->notifyPortStatusChange_1_1(
                    currentPortStatus_1_1, status);
                } else { // V1_0 callback
                    hidl_vec<V1_0::PortStatus> currentPortStatus;
                    Status status = getPortStatusHelper(&currentPortStatus_1_1, true);

                    currentPortStatus.resize(currentPortStatus_1_1.size());
                    for (unsigned long i = 0; i < currentPortStatus_1_1.size(); i++)
                        currentPortStatus[i] = currentPortStatus_1_1[i].status;
                    ret = payload->usb->mCallback_1_0->notifyPortStatusChange(
                        currentPortStatus, status);
                }
                if (!ret.isOk()) ALOGE("error %s", ret.description().c_str());
            } else {
                ALOGI("Notifying userspace skipped. Callback is NULL");
            }
            pthread_mutex_unlock(&payload->usb->mLock);
            break;
        }
        /* advance to after the next \0 */
        while (*cp++) {}
    }
}

void* work(void* param) {
    int epoll_fd, uevent_fd;
    struct epoll_event ev;
    int nevents = 0;
    struct data payload;
    DIR *dp;

    ALOGE("creating thread");

    dp = opendir(TYPEC_PATH);
    if (dp != NULL)
        class_typec = TYPEC_PATH;
    else
        class_typec = DUAL_ROLE_USB_PATH;

    closedir(dp);
    uevent_fd = uevent_open_socket(64*1024, true);

    if (uevent_fd < 0) {
        ALOGE("uevent_init: uevent_open_socket failed\n");
        return NULL;
    }

    payload.uevent_fd = uevent_fd;
    payload.usb = (android::hardware::usb::V1_1::implementation::Usb *)param;

    fcntl(uevent_fd, F_SETFL, O_NONBLOCK);

    ev.events = EPOLLIN;
    ev.data.ptr = (void *)uevent_event;

    epoll_fd = epoll_create(64);
    if (epoll_fd == -1) {
        ALOGE("epoll_create failed; errno=%d", errno);
        goto error;
    }

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, uevent_fd, &ev) == -1) {
        ALOGE("epoll_ctl failed; errno=%d", errno);
        goto error;
    }

    while (!destroyThread) {
        struct epoll_event events[64];

        nevents = epoll_wait(epoll_fd, events, 64, -1);
        if (nevents == -1) {
            if (errno == EINTR)
                continue;
            ALOGE("usb epoll_wait failed; errno=%d", errno);
            break;
        }

        for (int n = 0; n < nevents; ++n) {
            if (events[n].data.ptr)
                (*(void (*)(int, struct data *payload))events[n].data.ptr)
                    (events[n].events, &payload);
        }
    }

    ALOGI("exiting worker thread");
error:
    close(uevent_fd);

    if (epoll_fd >= 0)
        close(epoll_fd);

    return NULL;
}

void sighandler(int sig)
{
    if (sig == SIGUSR1) {
        destroyThread = true;
        ALOGI("destroy set");
        return;
    }
    signal(SIGUSR1, sighandler);
}

Return<void> Usb::setCallback(const sp<V1_0::IUsbCallback>& callback) {
    sp<IUsbCallback> callback_V1_1 = IUsbCallback::castFrom(callback);
    if (callback != NULL)
        if (callback_V1_1 == NULL)
            ALOGI("Registering 1.0 callback");

    pthread_mutex_lock(&mLock);
    if ((mCallback_1_0 == NULL && callback == NULL) ||
            (mCallback_1_0 != NULL && callback != NULL)) {
        mCallback_1_0 = callback;
        pthread_mutex_unlock(&mLock);
        return Void();
    }

    mCallback_1_0 = callback;
    ALOGI("registering callback");

    if (mCallback_1_0 == NULL) {
        if  (!pthread_kill(mPoll, SIGUSR1)) {
            pthread_join(mPoll, NULL);
            ALOGI("pthread destroyed");
        }
        pthread_mutex_unlock(&mLock);
        return Void();
    }

    destroyThread = false;
    signal(SIGUSR1, sighandler);

    if (pthread_create(&mPoll, NULL, work, this)) {
        ALOGE("pthread creation failed %d", errno);
        mCallback_1_0 = NULL;
    }
    pthread_mutex_unlock(&mLock);
    return Void();
}
}  // namespace implementation
}  // namespace V1_1
}  // namespace usb
}  // namespace hardware
}  // namespace android
