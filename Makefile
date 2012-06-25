UNAME := $(shell uname)
ifeq ($(UNAME), Linux)
# Linux
PLATFORM_OPTIONS = -lcrypto
else
ifeq ($(UNAME), Darwin)
# OS X
PLATFORM_OPTIONS = -lcrypto -force_cpusubtype_ALL -arch i386 -arch x86_64 -Wno-deprecated-declarations
else
MINGW = $(findstring MINGW32, $(UNAME))
ifneq ($(MINGW), "")
# WIN32
OPENSSL_DIR=/usr
PLATFORM_OPTIONS = -I$(OPENSSL_DIR)/include -L$(OPENSSL_DIR) -lcrypto -lgdi32
else
$(error Unknown platform)
endif
endif
endif

SOURCES = genpass.cpp
all:
	echo $(UNAME)
	# Build as C++ to catch easy bugs
	g++ -Wall -Werror -o genpass -x c++ $(SOURCES) $(PLATFORM_OPTIONS)
	# Actual compilation
	gcc -o genpass -x c $(SOURCES) $(PLATFORM_OPTIONS)
