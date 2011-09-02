UNIVERSAL_OPTIONS = -force_cpusubtype_ALL -arch i386 -arch x86_64
SOURCES = genpass.cpp
all:
	g++ -o genpass -lcrypto $(SOURCES) $(UNIVERSAL_OPTIONS)
