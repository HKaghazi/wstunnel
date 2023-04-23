# Compiler to use
CXX = g++

# Compiler flags
CXXFLAGS = -Wall -std=c++11

# Include directory for OpenSSL headers
OPENSSL_INCLUDE = /opt/homebrew/opt/openssl/include

# Library directory for OpenSSL libraries
OPENSSL_LIBDIR = /opt/homebrew/opt/openssl/lib

# Libraries to link with
LIBS = -lssl -lcrypto

# Source code files
SRCS = wstunnel.cpp

# Object files (generated automatically from source code files)
OBJS = $(SRCS:.cpp=.o)

# Executable file to generate
TARGET = build/wstunnel

all:
	$(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -L$(OPENSSL_LIBDIR) $(LIBS) $(OBJS) -o $(TARGET)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -I$(OPENSSL_INCLUDE) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
