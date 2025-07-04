#ifndef SNIFFER_PARAMS_H
#define SNIFFER_PARAMS_H

#include <unistd.h>  // Для getopt()
#include <stdbool.h>

// Параметры запуска
typedef struct {
    char *interface;    // Сетевой интерфейс (eth0, wlan0)
    char *filter_exp;   // Фильтр BPF (например, "tcp port 80")
    bool save_to_json;  // Сохранять в JSON?
    bool verbose;       // Подробный вывод?
} SnifferParams;

SnifferParams parse_args(int argc, char **argv);

#endif