#ifndef DELETE_COMMAND_H
#define DELETE_COMMAND_H

#include <stdbool.h>

bool delete_command(
    const char *filepath,
    ChainType target_chain,
    const char *target_line_str
);

#endif