# Makefile para el Laboratorio 1 – Cifrado simétrico y asimétrico
# Compila Lab1.cpp y enlaza con la biblioteca Crypto++

CXX      := g++
CXXFLAGS := -std=c++17 -Wall -O2
LDFLAGS  := -lcryptopp

TARGET   := lab1
SRC      := main.cpp

all: $(TARGET)

$(TARGET): $(SRC) aes_utils.h rsa_utils.h
	$(CXX) $(CXXFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean