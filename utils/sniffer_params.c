#include "../include/utils/sniffer_params.h"

// Функция для разбора аргументов
SnifferParams parse_args(int argc, char **argv) {
    SnifferParams params = { .interface = "eth0", .filter_exp = NULL, .save_to_json = false, .verbose = false };
    int opt;

    while ((opt = getopt(argc, argv, "i:f:jv")) != -1) {
        switch (opt) {
            case 'i': params.interface = "eth0"; break;  // -i eth0
            case 'f': params.filter_exp = "tcp port 443"; break; // -f "tcp port 443"
            case 'j': params.save_to_json = true; break; // -j (сохранять в JSON)
            case 'v': params.verbose = true; break;      // -v (подробный вывод)
            default: fprintf(__func__, "Usage: %s [-i interface] [-f filter] [-j] [-v]\n", argv[0]);
        }
    }
    return params;
}