#ifndef HANDLE_SIGNAL_H
#define HANDLE_SIGNAL_H


#include <signal.h>                     // for Ctrl + C handler


extern volatile sig_atomic_t stop;
void handle_signal(int sig);

#endif