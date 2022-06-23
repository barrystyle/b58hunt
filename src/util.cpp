#include <util.h>

template <typename T>
static T get_system_time()
{
    return std::chrono::duration_cast<T>(std::chrono::system_clock::now().time_since_epoch());
}

int64_t get_time_millis()
{
    return int64_t { get_system_time<std::chrono::milliseconds>().count() };
}

void return_on_sec()
{
    while (true) {
        if (get_time_millis() % 1000 == 0)
            return;
    }
}
