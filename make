
g++ -I./src -O3 -march=native src/util.cpp src/main.cpp -o b58hunt -lcrypto -lsecp256k1 -lpthread
