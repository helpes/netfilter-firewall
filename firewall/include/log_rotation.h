#ifndef LOG_ROTATION_H
#define LOG_ROTATION_H

#include <stdio.h>
#include <stdbool.h>

bool log_rotation(FILE **log_fp, int rotate, int rotation_size_mb);

#endif