#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <limits.h>
#include <string.h>

int validate_and_convert_line(const char *line_str)
{
    if (line_str == NULL) {
        return -1;
    }

    char *endptr;
    long target_line = strtol(line_str, &endptr, 10);
    if (*endptr != '\0') {
        return -1;
    } else if (target_line > INT_MAX || target_line < INT_MIN) {
        return -1;
    } else if (target_line <= 0) {
        return -1;
    }

    return (int)target_line;
}