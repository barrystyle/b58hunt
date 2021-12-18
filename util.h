#ifndef B58GEN_UTIL_H
#define B58GEN_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include <chrono>
#include <iostream>
#include <limits>

int64_t get_time_millis();
void return_on_sec();

#endif // B58GEN_UTIL_H
