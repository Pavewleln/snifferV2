# Сниффер

Легковесный анализатор сетевого трафика на языке C с поддержкой вывода в JSON.

## Установка

# Для Debian/Ubuntu
```bash
sudo apt install build-essential libpcap-dev libjansson-dev
```

# Сборка
```bash
git clone https://github.com/account/sniffer.git
cd sniffer
mkdir build
cd build
cmake ..
make
```

# Запуск
```bash
sudo ./sniffer [-i интерфейс] [-f фильтр] [-j] [-v]
```
