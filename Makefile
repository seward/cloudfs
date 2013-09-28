#
#  cloudfs: Makefile
#	By Benjamin Kittridge. Copyright (C) 2013, All rights reserved.
#
#

###################################################
# Config

-include config.mk
ifndef CONFIG
$(error Please run ./config.sh before running make)
endif 

###################################################
# Options

NAME =		cloudfs
VERSION =	0.1

BIN_PATH =	bin
BIN =		cloudfs

SRC_PATH =	src
SRC =		$(patsubst %.c,%.o,$(wildcard ${SRC_PATH}/*.c)) \
		$(patsubst %.c,%.o,$(wildcard ${SRC_PATH}/*/*.c)) \
		$(patsubst %.c,%.o,$(wildcard ${SRC_PATH}/*/*/*.c))

LINK_ARG =	-lpthread ${LDFLAGS}
COMPILE_ARG =	-g -iquote ${SRC_PATH} -Wimplicit -Werror -Wall -Wextra \
		-Wno-unused-result -Wno-missing-field-initializers \
		-Wno-unused-parameter -Wno-sign-compare --std=gnu99 \
		-D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 ${CFLAGS}

INSTALL_PATH =	/usr/sbin

###################################################
# Additional extensions

ifeq ($(FUSE), 1)
#SRC +=		${SRC_PATH}/infr/fuse.o
endif

###################################################
# Build

all: info build

info:
	@echo "BUILDING: ${NAME}"

-include $(SRC:.o=.d)

.SUFFIXES:
.SUFFIXES: .c .so .o
.c.o:
	@echo "COMPILE:  $<"
	@${CC} -MD -c $< -o $@ ${COMPILE_ARG}

build: ${SRC}
	@mkdir -p ${BIN_PATH}
	@echo "LINK:     ${BIN_PATH}/${BIN}"
	@${CC} -o ${BIN_PATH}/${BIN} ${SRC} ${LINK_ARG}
	@echo
	
install:
	@install ${BIN_PATH}/${BIN} ${INSTALL_PATH}/${BIN}
	@echo "Program installed in ${INSTALL_PATH}/${BIN}"
	
uninstall:
	@rm -f ${INSTALL_PATH}/${BIN}

clean:
	@rm -f ${BIN_PATH}/${BIN} ${SRC} $(SRC:.o=.d)
	
distclean: clean
	@rm -f config.mk
	