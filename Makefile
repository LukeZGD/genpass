UNAME := $(shell uname)
ARCH := $(shell uname -m)

ifeq ($(UNAME), Linux)
# Linux
PLATFORM_OPTIONS = -lcrypto
else
ifeq ($(UNAME), Darwin)

# Check for Apple Silicon (M1/M2/M3)
ifeq ($(ARCH), arm64)
    # Check for Homebrew OpenSSL on Apple Silicon
    HOMEBREW_ARM_OPENSSL := $(shell [ -d /opt/homebrew/opt/openssl@3 ] && echo found)
    ifeq ($(HOMEBREW_ARM_OPENSSL), found)
        PLATFORM_OPTIONS = -lcrypto -Wno-deprecated-declarations -L/opt/homebrew/opt/openssl@3/lib -I/opt/homebrew/opt/openssl@3/include
    else
        # Try regular Homebrew OpenSSL
        HOMEBREW_ARM_OPENSSL := $(shell [ -d /opt/homebrew/opt/openssl ] && echo found)
        ifeq ($(HOMEBREW_ARM_OPENSSL), found)
            PLATFORM_OPTIONS = -lcrypto -Wno-deprecated-declarations -L/opt/homebrew/opt/openssl/lib -I/opt/homebrew/opt/openssl/include
        endif
    endif
else
    # Intel Mac - check for Homebrew first, then MacPorts
    HOMEBREW_INTEL_OPENSSL := $(shell [ -d /usr/local/opt/openssl@3 ] && echo found)
    ifeq ($(HOMEBREW_INTEL_OPENSSL), found)
        PLATFORM_OPTIONS = -lcrypto -Wno-deprecated-declarations -L/usr/local/opt/openssl@3/lib -I/usr/local/opt/openssl@3/include
    else
        # Check for regular Homebrew OpenSSL
        HOMEBREW_INTEL_OPENSSL := $(shell [ -d /usr/local/opt/openssl ] && echo found)
        ifeq ($(HOMEBREW_INTEL_OPENSSL), found)
            PLATFORM_OPTIONS = -lcrypto -Wno-deprecated-declarations -L/usr/local/opt/openssl/lib -I/usr/local/opt/openssl/include
        else
            MACPORTS_OPENSSL := $(shell [ -d /opt/local/lib/openssl-3 ] && echo found)
            ifeq ($(MACPORTS_OPENSSL), found)
                PLATFORM_OPTIONS = -lcrypto -Wno-deprecated-declarations -L/opt/local/lib/openssl-3 -I/opt/local/include/openssl-3
            else
                PLATFORM_OPTIONS = -lcrypto -Wno-deprecated-declarations -L/opt/local/lib -I/opt/local/include
            endif
        endif
    endif
endif

ifneq ($(OPENSSL_DIR),)
PLATFORM_OPTIONS += -I$(OPENSSL_DIR)/include -L$(OPENSSL_DIR)/lib
endif

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
	@echo "Building for $(UNAME) on $(ARCH) architecture"
	# Build as C++ to catch easy bugs
	g++ -Wall -Werror -o genpass -x c++ $(SOURCES) $(PLATFORM_OPTIONS)
	# Actual compilation
	gcc -o genpass -x c $(SOURCES) $(PLATFORM_OPTIONS)
