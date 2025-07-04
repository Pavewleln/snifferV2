cmake_minimum_required(VERSION 3.10)
project(sniffer LANGUAGES C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "-Wall -Wextra")

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)
pkg_check_modules(JANSSON REQUIRED jansson)

set(SOURCES
    sniffer.c
    utils/handle_signal.c
    utils/sniffer_params.c
)

# 4. Список заголовочных файлов
set(HEADERS
    include/sniffer.h
    include/utils/handle_signal.h
    include/utils/sniffer_params.h
)

# 5. Создаём исполняемый файл
add_executable(sniffer ${SOURCES} ${HEADERS})

# 6. Подключаем заголовки
target_include_directories(sniffer PRIVATE include)

# 7. Линкуем библиотеки
target_link_libraries(sniffer PRIVATE ${PCAP_LIBRARIES} ${JANSSON_LIBRARIES})

# 8. Указываем, куда класть бинарник
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})