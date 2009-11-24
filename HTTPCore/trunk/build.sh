#!/bin/bash
PATH="/usr/local/sbin:/usr/sbin:/sbin:/bin:/usr/bin"

if [ -d "release" ]
 then
  echo "Fhscan path already exists"
 else
   mkdir release
fi

# Carry out specific functions when asked to by the system
case "$1" in
  clean)
	echo "cleaning files..."
  	rm -rf *.o 
	rm -rf release/Fhscan 
	rm -rf HTTPCore14.so 
	rm -rf /usr/lib/libHTTPCore.so 
	rm -rf /usr/include/HTTPCore
  ;;
  static)
  	echo starting static build...
	g++  -DLINUX  -D_ZLIB_SUPPORT_  -lpthread -lssl -lz HTTPCore/*.cpp Scanner/*.cpp Scanner/Input/*.cpp Scanner/Reporting/*.cpp -o release/Fhscan
  ;;
  debug)
        echo starting static build...
        echo needed to debug fhscan with gdb: gdb --args Fhscan --hosts 19.168.0.1 --verbose		
        g++  -ggdb -g3 -O0 -fno-inline  -DLINUX -D_ZLIB_SUPPORT_  -lpthread -lssl -lz HTTPCore/*.cpp Scanner/*.cpp Scanner/Input/*.cpp Scanner/Reporting/*.cpp -o release/Fhscan

  ;;
  install)
	# Make sure that you are root
        if [ "$(id -u)" != "0" ]; then
           echo "This script must be run as root. Try static build instead"
           exit 1
        fi

	echo "Starting dynamic build..."
	g++  -DLINUX  -D_ZLIB_SUPPORT_  -c -fPIC HTTPCore/*.cpp
	g++ -shared -o HTTPCore14.so -fPIC *.o

	echo installing HTTPCore library into /usr/lib
	cp HTTPCore14.so /usr/lib/libHTTPCore.so

	echo installing headers into /usr/include/HTTPCore/
	mkdir /usr/include/HTTPCore
	cp HTTPCore/*.h /usr/include/HTTPCore/

	echo Building Fhscan HTTP Scanner
	g++  -lpthread -lssl -lz -lHTTPCore -DLINUX -D_ZLIB_SUPPORT_ Scanner/*.cpp Scanner/Input/*.cpp Scanner/Reporting/*.cpp -o release/Fhscan
	rm -rf *.o
	;;
  *)
    echo "FHscan v1.4 Build script"
    echo "Usage: ./build.sh  {static|install|clean}"
    echo "       *NOTE* install build will add libHTTPCore.so to /usr/lib and install required headers. root privileges are required."
    exit 1
    ;;
esac

exit 0


