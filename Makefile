CXX = clang++

LDFLAGS = -flto=thin \
		  -framework Metal \
		  -framework Foundation \
		  -fsanitize=address \
		  -fuse-ld=mold

CFLAGS  = -fwrapv \
		  -fno-strict-aliasing \
		  -fno-delete-null-pointer-checks \
		  -funsigned-char \
		  -Wall \
		  -Wstring-compare \
		  -Wuninitialized \
		  -std=c++17 \
		  -g3

SRCS = metal.m main.cc common.cc
OBJS = $(patsubst %.cc,build/%.o,$(patsubst %.m,build/%.o,$(SRCS)))

build/%.o: %.cc
	@mkdir -p build
	$(CXX) $(CFLAGS) -o $@ -c $<

build/%.o: %.mm
	@mkdir -p build
	$(CXX) $(CFLAGS) -o $@ -c $<

build/main: $(OBJS)
	$(CXX) $(LDFLAGS) $(OBJS) -o $@

clean:
	rm -rf build

all: build/main

.PHONY: all clean
