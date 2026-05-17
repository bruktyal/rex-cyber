# ================================================================
# Rex IoT Security Framework — C++ Core Build System
# Rex Cybersecurity Project
# ================================================================

CXX      := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -O2 -I include
TARGET   := build/rex_gateway

SRCS := src/gateway_security.cpp
OBJS := $(SRCS:src/%.cpp=build/%.o)

.PHONY: all clean run dll

all: build $(TARGET)

build:
	mkdir -p build

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^
	@echo "  [Rex] Build successful: $(TARGET)"

build/%.o: src/%.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

dll: build
	$(CXX) $(CXXFLAGS) -DBUILD_DLL -shared -fPIC -static-libgcc -static-libstdc++ src/gateway_security.cpp src/c_api.cpp -o build/rex_gateway.dll
	@echo "  [Rex] DLL build successful: build/rex_gateway.dll"

run: all
	./$(TARGET)

clean:
	rm -rf build/
	@echo "  [Rex] Build directory cleaned."

help:
	@echo ""
	@echo "  Rex IoT Security — C++ Core Build"
	@echo "  ──────────────────────────────────────────────────"
	@echo "  make        — Build the gateway processor executable"
	@echo "  make dll    — Build the gateway shared library (.dll)"
	@echo "  make run    — Build and run the demo executable"
	@echo "  make clean  — Remove build artifacts"
	@echo ""
