
g++ -I./src -O3 -march=native src/util.cpp src/main.cpp src/sha256*.cpp src/ripemd*.cpp -o b58hunt -lsecp256k1 -lpthread
