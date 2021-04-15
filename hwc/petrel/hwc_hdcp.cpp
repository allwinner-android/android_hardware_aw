
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#include "hwc.h"

#define AVMUTE_PATH         "/sys/class/hdmi/hdmi/attr/avmute"
#define HDCP_ENABLE_PATH    "/sys/class/hdmi/hdmi/attr/hdcp_enable"
#define HDCP_STATUS_PATH    "/sys/class/hdmi/hdmi/attr/hdcp_status"
#define HDCP_VERSION_PATH   "/sys/class/hdmi/hdmi/attr/hdcp_type"

#define HDCP_STATUS_DISABLE (0)
#define HDCP_STATUS_ING     (1)
#define HDCP_STATUS_FAILED  (2)
#define HDCP_STATUS_SUCCESS (3)

static int writeFile(const char *path, const char *value)
{
    int fd = open(path, O_WRONLY, 0);
    if (fd == -1) {
        ALOGE("open file '%s' error, %s", path, strerror(errno));
        return -1;
    }
    int written = write(fd, value, strlen(value));
    close(fd);
    ALOGE("write '%s' = %s written(%d)", path, value, written);
    return 0;
}

static int read_from_file(const char *path, char *buf, size_t size)
{
    int fd = open(path, O_RDONLY, 0);
    if (fd == -1) {
        ALOGE("Could not open '%s', %s(%d)", path, strerror(errno), errno);
        return -1;
    }
    ssize_t count = read(fd, buf, size - 1);
    if (count > 0)
        buf[count] = '\0';
    else
        buf[0] = '\0';

    close(fd);
    return count;
}

static int get_hdcp_status()
{
    char buf[32];
    int count = read_from_file(HDCP_STATUS_PATH, buf, 32);
    return buf[0];
}

static const char * get_hdcp_version()
{
    char buf[32];
    int count = read_from_file(HDCP_VERSION_PATH, buf, 32);
    char code = buf[0];

    switch (code) {
        case 0:  return "hdcp14";
        case 1:  return "hdcp22";
        default: return "none";
    }
    return "none";
}

static int is_hdcp_config()
{
    int widevine = property_get_int32("ro.sys.widevine_oemcrypto_level", 0);
    int hdcpcfg  = property_get_int32("persist.sys.disp.hdcp_cfg", 0);
    int __cfg = (widevine && hdcpcfg);
    return __cfg;
}


static pthread_t __hwc_hdcp_thread;
static int __hwc_hdcp_enable;
static int __hwc_hdcp_status;

int hwc_hdcp_enable()
{
    ALOGD("hwc hdcp enable");
    blank_disp(0);
    usleep(1000 * 100);

    writeFile(AVMUTE_PATH, "1\n");
    usleep(1000 * 32);
    if (writeFile(HDCP_ENABLE_PATH, "1\n") != 0) {
        ALOGE("hdcp enable error");
        writeFile(AVMUTE_PATH, "0\n");
        return -1;
    }

    int status;
    int timeout = 20;
    while (timeout) {
        status = get_hdcp_status();
        if (status != HDCP_STATUS_ING)
            break;

        usleep(1000 * 100);
        timeout--;
    }

    usleep(1000 * 32);
    writeFile(AVMUTE_PATH, "0\n");
    return 0;
}

static void *hwc_hdcp_thread(void * /*data*/)
{
    while (1) {
        int state = get_hdcp_status();
        if (__hwc_hdcp_status != state) {
            __hwc_hdcp_status = state;
            char buf[32];
            sprintf(buf, "%d", __hwc_hdcp_status);
            property_set("sys.disp.hdcp_status", buf);
            property_set("sys.disp.hdcp_version",get_hdcp_version());
        }

        if (is_hdcp_config() && !__hwc_hdcp_enable && property_get_int32("service.bootanim.exit", 0)) {
            hwc_hdcp_enable();
            __hwc_hdcp_enable = 1;
        }
        usleep(1000 * 100);
    }
    return 0;
}

int hwc_hdcp_init()
{
    if (is_hdcp_config() == 0) {
        ALOGD("hdcp is not config");

        property_set("sys.disp.hdcp_status", "0");
        property_set("sys.disp.hdcp_version","none");
        goto _create_thread;
    }

/*
    hwc_hdcp_enable();
    __hwc_hdcp_enable = 1;
*/

_create_thread:
    pthread_create(&__hwc_hdcp_thread, NULL, hwc_hdcp_thread, 0);
    return 0;
}
