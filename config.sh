#!/bin/sh

###########################################################################
# Re(set) environment variables

if test -z "$CC"; then
	CC=gcc
fi

FUSE=1
CFLAGS=
LDFLAGS=

if [ -f /etc/lsb-release ]; then
	. /etc/lsb-release
fi

###########################################################################
# Check for options

usage() {
	echo >&2
	echo "Usage: $0 [OPTIONS]..." >&2
	echo "       --help                  Display this help message" >&2
	echo "       --with-cc[=bin]         Specifies the C compiler to use" >&2
	echo "       --with-fuse[=path]      Specifies path to the fuse library" >&2
	echo "       --with-ssl[=path]       Specifies path to openssl library" >&2
	echo "       --with-zlib[=path]      Specifies path to zlib installation" >&2
	echo "       --with-curl[=path]      Specifies path to the curl library" >&2
	echo "       --without-fuse          Disables fuse support" >&2
	echo >&2
	exit 1
}

while getopts ":h-:" OPTRET; do
	case "${OPTRET}" in
		-)
			case "${OPTARG}" in
				with-cc) ;;
				with-cc=*)
					CC=${OPTARG#*=}
					;;
				with-fuse) ;;
				with-fuse=*)
					FUSE_PATH=${OPTARG#*=}
					;;
				without-fuse)
					FUSE=0
					;;
				with-ssl) ;;
				with-ssl=*)
					SSL_PATH=${OPTARG#*=}
					;;
				with-zlib) ;;
				with-zlib=*)
					ZLIB_PATH=${OPTARG#*=}
					;;
				with-curl) ;;
				with-curl=*)
					CURL_PATH=${OPTARG#*=}
					;;
				help)
					usage
					;;
				*)
					echo "Unknown option --${OPTARG}" >&2
					usage
					;;
			esac
			;;
		h)
			usage
			;;
		*)
			echo "Unknown option '-${OPTARG}'" >&2
			usage
			;;
	esac
done

###########################################################################
# Check platform

echo -n "* Checking for platform ... "
case `uname -s` in
	Linux)
		CFLAGS="${CFLAGS} -DOS_LINUX"
		;;
	FreeBSD)
		CFLAGS="${CFLAGS} -DOS_FREEBSD"
		;;
	SunOS)
		CFLAGS="${CFLAGS} -DOS_SOLARIS"
		;;
	Darwin)
		CFLAGS="${CFLAGS} -DOS_DARWIN"
		;;
	*)
		CFLAGS="${CFLAGS} -DOS_OTHER"
		;;
esac
echo "done"

###########################################################################
# Check for fuse

if [ "${FUSE}" -eq 1 ]; then
	echo -n "* Checking for fuse ... "
	if [ "${FUSE_PATH}x" != "x" ]; then
		LDFLAGS="${LDFLAGS} -L${FUSE_PATH}/lib"
		CFLAGS="${CFLAGS} -I${FUSE_PATH}/include"
	fi
	OLD_LDFLAGS="${LDFLAGS}"
	LDFLAGS="${LDFLAGS} -lfuse"
	XCFLAGS="-D_FILE_OFFSET_BITS=64"
	
	${CC} -x c - ${CFLAGS} ${LDFLAGS} ${XCFLAGS} -o /dev/null 2>/dev/null <<EOF
		#include <fuse.h>
		void main() { fuse_interrupted(); }
EOF
	if [ "$?" != 0 ]; then
		LDFLAGS="${OLD_LDFLAGS} -lfuse"
			
		${CC} -x c - ${CFLAGS} ${LDFLAGS} ${XCFLAGS} -o /dev/null 2>/dev/null <<EOF
			#include <fuse.h>
			void main() { fuse_interrupted(); }
EOF
		if [ "$?" != 0 ]; then
			echo "failed"
			echo "Please make sure libfuse is installed or use --with-fuse=DIR"
			if [ "${DISTRIB_ID}x" = "Ubuntux" ]; then
				echo "Try: sudo apt-get install libfuse-dev"
			fi
			exit
		fi
	fi
	echo "done"
fi

###########################################################################
# Check for openssl

echo -n "* Checking for openssl ... "
if [ "${SSL_PATH}x" != "x" ]; then
	LDFLAGS="${LDFLAGS} -L${SSL_PATH}/lib"
	CFLAGS="${CFLAGS} -I${SSL_PATH}/include"
fi
LDFLAGS="${LDFLAGS} -lssl -lcrypto"
	
${CC} -x c - ${CFLAGS} ${LDFLAGS} -o /dev/null 2>/dev/null <<EOF
	#include <openssl/md5.h>
	#include <openssl/sha.h>
	#include <openssl/evp.h>
	void main() { EVP_sha1(); }
EOF
if [ "$?" != 0 ]; then
	echo "failed"
	echo "Please make sure openssl is installed or use --with-ssl=DIR"
	if [ "${DISTRIB_ID}x" = "Ubuntux" ]; then
		echo "Try: sudo apt-get install libssl-dev"
	fi
	exit
fi
echo "done"

###########################################################################
# Check for zlib

echo -n "* Checking for zlib ... "
if [ "${ZLIB_PATH}x" != "x" ]; then
	LDFLAGS="${LDFLAGS} -L${ZLIB_PATH}/lib"
	CFLAGS="${CFLAGS} -I${ZLIB_PATH}/include"
fi
LDFLAGS="${LDFLAGS} -lz"
	
${CC} -x c - ${CFLAGS} ${LDFLAGS} -o /dev/null 2>/dev/null <<EOF
	#include <zlib.h>
	void main() { inflateInit(NULL); }
EOF
if [ "$?" != 0 ]; then
	echo "failed"
	echo "Please make sure zlib is installed or use --with-zlib=DIR"
	if [ "${DISTRIB_ID}x" = "Ubuntux" ]; then
		echo "Try: sudo apt-get install zlib1g-dev"
	fi
	exit
fi
echo "done"

###########################################################################
# Check for curl

echo -n "* Checking for curl ... "
if [ "${CURL_PATH}x" != "x" ]; then
	LDFLAGS="${LDFLAGS} -L${CURL_PATH}/lib"
	CFLAGS="${CFLAGS} -I${CURL_PATH}/include"
fi
LDFLAGS="${LDFLAGS} -lcurl"
	
${CC} -x c - ${CFLAGS} ${LDFLAGS} -o /dev/null 2>/dev/null <<EOF
	#include <curl/curl.h>
	void main() { curl_global_init(0); }
EOF
if [ "$?" != 0 ]; then
	echo "failed"
	echo "Please make sure curl is installed or use --with-curl=DIR"
	if [ "${DISTRIB_ID}x" = "Ubuntux" ]; then
		echo "Try: sudo apt-get install libcurl4-openssl-dev"
	fi
	exit
fi
echo "done"

###########################################################################
# Write config

echo "* Config completed successfully"
echo "Run make to compile"

echo "# Automaticly generated, do not edit"  > config.mk
echo "# Build: ${0} ${@}"                   >> config.mk
echo "CONFIG = 1"                           >> config.mk
echo "CC = ${CC}"                           >> config.mk
echo "FUSE = ${FUSE}"                       >> config.mk
echo "CFLAGS = ${CFLAGS}"                   >> config.mk
echo "LDFLAGS = ${LDFLAGS}"                 >> config.mk
