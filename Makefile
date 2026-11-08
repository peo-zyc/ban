# 便捷构建（不依赖 cmake）
CXX      ?= g++
VERSION  ?= $(shell sed -n 's/^project(ban VERSION \([0-9][0-9.]*\).*/\1/p' CMakeLists.txt)
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Wpedantic -DBAN_VERSION=\"$(VERSION)\"
LDFLAGS  ?= -static-libstdc++ -static-libgcc
SRCS     := $(wildcard src/*.cpp)
HDRS     := $(wildcard src/*.h)

PREFIX   ?= /usr/local

.PHONY: all clean install test

all: ban

ban: $(SRCS) $(HDRS)
	$(CXX) $(CXXFLAGS) -Isrc -o $@ $(SRCS) $(LDFLAGS)

test: ban_tests
	./ban_tests

ban_tests: tests/unit_main.cpp src/util.cpp src/model.cpp src/json.cpp $(HDRS)
	$(CXX) $(CXXFLAGS) -Isrc -o $@ tests/unit_main.cpp src/util.cpp src/model.cpp src/json.cpp

install: ban
	install -Dm755 ban $(DESTDIR)$(PREFIX)/bin/ban
	install -Dm644 systemd/ban-restore.service $(DESTDIR)$(PREFIX)/lib/systemd/system/ban-restore.service
	install -Dm644 systemd/ban-refresh.service $(DESTDIR)$(PREFIX)/lib/systemd/system/ban-refresh.service
	install -Dm644 systemd/ban-refresh.timer   $(DESTDIR)$(PREFIX)/lib/systemd/system/ban-refresh.timer

clean:
	rm -f ban ban_tests
