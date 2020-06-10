# Makefile for CPE464 library

BUILD_MAJOR=2
BUILD_MINOR=20
TEST=test

CC = g++
CFLAGS = 

LIBPATH=libcpe464
NETWORK=libcpe464/networks

PACKAGES = sendtoErr sendErr checksum
HDRS = $(shell cd $(NETWORK) && ls *.hpp *.h 2> /dev/null)
SRCS = $(shell find . -name "*.cpp" -o -name "*.c" 2> /dev/null)
OBJS = $(shell find . -name "*.cpp" -o -name "*.c" 2> /dev/null | sed s/\.c[p]*$$/\.o/ )
HFILE = cpe464


CPE464_VER = libcpe464.$(BUILD_MAJOR).$(BUILD_MINOR)
CPE464_LIB = $(CPE464_VER).a

all: header $(OBJS) link combHeader get_Makefile clean
	@echo "-------------------------------"

test: test_setup echo all

test_setup:
	$(eval CPE464_VER = libcpe464.$(TEST))
	$(eval CPE464_LIB = $(CPE464_VER).a)

	
partial: header $(OBJS)
	@echo "-------------------------------"

echo:
	@echo $(OBJS)
	@echo "BUILD_MAJOR: " $(BUILD_MAJOR) "BUILD_MINOR: " $(BUILD_MINOR)
	@echo "CPE464_VER: $(CPE464_VER)"
	@echo "CPE464_LIB: $(CPE464_LIB) "

version:
	@echo $(BUILD_MAJOR).$(BUILD_MINOR) 

header:
	@echo "-------------------------------"
	@echo "Building $(CPE464_LIB) Objects"

.cpp.o:
	@echo "-------------------------------"
	@echo "  C++ Compiling $@"
	$(V)$(CC) -c $(CFLAGS) $< -o $@ $(LIBS)
.c.o:
	@echo "-------------------------------"
	@echo "  C Compiling $@"
	$(V)$(CC) -c $(CFLAGS) $< -o $@ $(LIBS)

link:
	@echo "-------------------------------"
	@echo "Loading objects into $(CPE464_LIB) library"
	$(V)ar -rcv $(CPE464_LIB) $(OBJS)
	@echo "-------------------------------"
	@echo "Done creating: $(CPE464_LIB) library"

combHeader:
	@echo "-------------------------------"
	@echo "Creating: cpe464.h"
	@cd $(NETWORK) && cat $(HDRS) > ../../$(HFILE).h

		
get_Makefile:
	-@cp -f  ./$(LIBPATH)/userfiles/* .
	@if [ -f Makefile ]; then \
		echo "*********************************************";  \
		echo ""; echo "You already have a file called Makefile."; \
		echo "Creating an example makefile called Makefile2 instead. "; \
		echo "(you can delete Makefile2 if you don't need it)";  \
		echo "Makefile2 shows how to link in the libcpe464 library."; echo "";  \
		mv -f example.mk Makefile2; fi
	@if [ ! -f Makefile ]; then  \
		echo "*********************************************";  \
		echo ""; echo "Creating an example Makefile for you."; \
		echo "You need to modify this Makefile to meet your needs."; \
		echo "This Makefile shows how to link in the libcpe464 library."; echo ""; \
		mv -f example.mk Makefile; fi
	
	
# clean targets for Solaris and Linux
clean: 
	-@find $(CURDIR) -name "*.o" | xargs rm -f

clean-full: clean
	-@rm -f ../*libcpe464*.a
