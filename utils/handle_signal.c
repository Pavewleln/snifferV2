#include "../include/utils/handle_signal.h"


volatile sig_atomic_t stop = 0;
void handle_signal(int sig){ stop = 1; };