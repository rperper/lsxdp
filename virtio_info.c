/* Copyright (c) 2020 - 2020 LiteSpeed Technologies Inc.  See LICENSE. */

#include "lsxdp.h"

#include <stdio.h>
#include <unistd.h>

#define INFO_SIZE 512 // a line or whatever

int debug_message(const char *format, ...);
#define DEBUG_MESSAGE debug_message

static int get_cpus(const char *dev, int *cpus, char *err_msg, int err_len)
{
    char *file = "/proc/cpuinfo";
    char line[INFO_SIZE];
    ssize_t rc;
    FILE *fh;
    int found_cpus = 0;

    fh = fopen(file, "r");
    if (!fh)
    {
        int err = errno;
        DEBUG_MESSAGE("Error in fopen of %s: %s\n", file, strerror(err));
        snprintf(err_msg, err_len, "Error in open of %s: %s", file, strerror(err));
        return -1;
    }
    while (fgets(line, sizeof(line), fh))
    {
        const char *prefix = "cpu cores";
        if (!strncmp(line, prefix, sizeof(prefix)))
        {
            char *colon = strchr(&line[sizeof(prefix)], ':');
            if (!colon)
            {
                DEBUG_MESSAGE("%s found without colon?\n", prefix);
                snprintf(err_msg, err_len, "Expected ':' in line with %s.  "
                         "Check %s", prefix, file);
                fclose(fh);
                return -1;
            }
            ++colon;
            *cpus = atoi(colon);
            DEBUG_MESSAGE("CPUs found: %d: in: %s", *cpus, colon);
            found_cpus = 1;
            if (!*cpus)
            {
                DEBUG_MESSAGE("Unexpected value of zero for CPUs\n");
                snprintf(err_msg, err_len, "CPUs expected to be non-zero");
                fclose(fh);
                return -1;
            }
            break;
        }
    }
    fclose(fh);
    if (found_cpus)
        return 0;
    DEBUG_MESSAGE("%s not found\n", "Queues");
    snprintf(err_msg, err_len, "%s not found using ethtool - validate device",
             "Queues");
    return -1;
}


static int get_queues(const char *dev, int *queues, char *err_msg, int err_len)
{
    char cmd[INFO_SIZE];
    char line[INFO_SIZE];
    ssize_t rc;
    FILE *fh;
    int found_current = 0;
    int found_queues = 0;

    snprintf(cmd, sizeof(cmd), "ethtool -l %s", dev);
    DEBUG_MESSAGE("get_queues, using cmd: '%s'\n", cmd);
    fh = popen(cmd, "r");
    if (!fh)
    {
        int err = errno;
        DEBUG_MESSAGE("Error in popen of %s: %s\n", cmd, strerror(err));
        snprintf(err_msg, err_len, "Error in open of %s: %s", cmd, strerror(err));
        return -1;
    }
    while (fgets(line, sizeof(line), fh))
    {
        if (!found_current)
        {
            const char *prefix = "Current hardware settings";
            if (!strncmp(line, prefix, sizeof(prefix) - 1))
            {
                DEBUG_MESSAGE("Current hardware settings found\n");
                found_current = 1;
                break; // Don't keep looking, queues past this don't count!
            }
        }
        const char *prefix = "Combined:";
        if (!strncmp(line, prefix, sizeof(prefix)))
        {
            int *found = queues;
            char *what = "Queues";
            *found = atoi(&line[sizeof(prefix)] + 1);
            DEBUG_MESSAGE("%s found: %d: in: %s", what, *found,
                          &line[sizeof(prefix)] + 1);
            found_queues = 1;
            if (!*found)
            {
                DEBUG_MESSAGE("Unexpected value of zero for %s\n", what);
                snprintf(err_msg, err_len, "%s expected to be non-zero", what);
                pclose(fh);
                return -1;
            }
            break;
        }
    }
    pclose(fh);
    if (found_queues)
        return 0;
    DEBUG_MESSAGE("%s not found\n", "Queues");
    snprintf(err_msg, err_len, "%s not found using ethtool - validate device",
             "Queues");
    return -1;
}


static int is_virtio(const char *dev, char *err_msg, int err_len)
{
    char link_file[INFO_SIZE];
    char link[INFO_SIZE];
    ssize_t rc;
    snprintf(link_file, sizeof(link_file),
             "/sys/class/net/%s/device/driver/module", dev);
    rc = readlink(link_file, link, sizeof(link) - 1);
    if (rc == -1)
    {
        int err = errno;
        DEBUG_MESSAGE("Error in readlink of %s: %s\n", link_file, strerror(err));
        snprintf(err_msg, err_len, "Error in readlink of %s: %s\n", link_file,
                 strerror(err));
        return -1;
    }
    link[rc] = 0;
    if (strstr(link, "virtio_net"))
    {
        DEBUG_MESSAGE("Is virtio_net\n");
        return 1;
    }
    DEBUG_MESSAGE("NOT virtio_net\n");
    return 0;
}


int xdp_get_virtio_info(const char *dev, int *queues, int *cpus, char *err_msg,
                        int err_len)
{
    int rc;
    *err_msg = 0;
    DEBUG_MESSAGE("xdp_get_virtio_info(%s)\n", dev);
    rc = is_virtio(dev, err_msg, err_len);
    if (rc == 1)
    {
        if (!get_cpus(dev, cpus, err_msg, err_len) &&
            !get_queues(dev, queues, err_msg, err_len))
        {
            if (*queues > 2 * *cpus)
            {
                DEBUG_MESSAGE("For now if the (number of queues) is > 2 * "
                              "(number of CPUs) use 2 * (number of CPUs) as "
                              "(number of queues) -> %d\n", 2 * *cpus);
                *queues = 2 * *cpus;
            }
            return 1;
        }
        return -1;
    }
    return rc;
}

        



