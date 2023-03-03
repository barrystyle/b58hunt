CC=g++
CPPFLAGS=-O2 -g -I./ -I./src -I./src/hash -std=c++11 -march=native -Wno-unused-result
LDFLAGS=
LDLIBS=-lstdc++ -lsecp256k1 -lpthread

SOURCES= \
	src/main.cpp \
	src/util.cpp \
	src/hash/ripemd160.cpp \
	src/hash/ripemd160_sse.cpp \
	src/hash/sha256.cpp \
	src/hash/sha256_sse.cpp

OBJECTS=$(SOURCES:.cpp=.o)
OUTPUT=b58hunt

all: clean $(SOURCES) $(OUTPUT)

$(OUTPUT): $(OBJECTS)
	$(CC) $(OBJECTS) $(LDLIBS) $(LDFLAGS) -o $@

.cpp.o:
	$(CC) $(CPPFLAGS) -c $< -o $@

clean:
	rm -f b58hunt
	rm -f *.o
	rm -f */*.o
	rm -f */*/*.o
