#include <stdio.h>
#include <string.h>
#include <ifaddrs.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CFNetwork/CFNetwork.h>
#include "fishhook.h"

static int (*orig_getifaddrs)(struct ifaddrs **);

int fake_getifaddrs(struct ifaddrs **ifap) {
    int ret = orig_getifaddrs(ifap);
    if (ret == 0) {
        struct ifaddrs *curr = *ifap;
        struct ifaddrs *prev = NULL;
        while (curr) {
            if (curr->ifa_name && (strncmp(curr->ifa_name, "utun", 4) == 0 || 
                                   strncmp(curr->ifa_name, "ipsec", 5) == 0 || 
                                   strncmp(curr->ifa_name, "ppp", 3) == 0)) {
                if (prev) {
                    prev->ifa_next = curr->ifa_next;
                } else {
                    *ifap = curr->ifa_next;
                }
            } else {
                prev = curr;
            }
            curr = curr->ifa_next;
        }
    }
    return ret;
}

static CFDictionaryRef (*orig_CFNetworkCopySystemProxySettings)(void);

CFDictionaryRef fake_CFNetworkCopySystemProxySettings(void) {
    return NULL; 
}

__attribute__((constructor)) static void initialize() {
    struct rebinding rebindings[] = {
        {"getifaddrs", fake_getifaddrs, (void **)&orig_getifaddrs},
        {"CFNetworkCopySystemProxySettings", fake_CFNetworkCopySystemProxySettings, (void **)&orig_CFNetworkCopySystemProxySettings}
    };
    rebind_symbols(rebindings, 2);
}
