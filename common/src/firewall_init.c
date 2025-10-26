#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include "firewall_config.h"

bool init_env(void)
{
    if (access(FIREWALL_CONFIG_DIR, F_OK) == -1) {
        if (mkdir(FIREWALL_CONFIG_DIR, 0755) == -1) {
            return false;
        }
    }
    if (access(LOG_DIR, F_OK) == -1) {
        if (mkdir(LOG_DIR, 0755) == -1) {
            return false;
        }
    }
    if (access(FIREWALL_CONFIG_FILE, F_OK) == -1) {
        FILE *fp = fopen(FIREWALL_CONFIG_FILE, "w");
        if (fp == NULL) {
            return false;
        }
        fclose(fp);
    }
    if (access(RULE_FILE, F_OK) == -1) {
        FILE *fp = fopen(RULE_FILE, "w");
        if (fp == NULL) {
            return false;
        }
        fclose(fp);
    }
    if (access(LOG_FILE, F_OK) == -1) {
        FILE *fp = fopen(LOG_FILE, "w");
        if (fp == NULL) {
            return false;
        }
        fclose(fp);
    }

    return true;
}