#ifndef LOGGING_COMMAND_H
#define LOGGING_COMMAND_H

#include <stdbool.h>
#include "firewall_config.h"

bool logging_command(const char *filepath, LogStatus logging);

#endif