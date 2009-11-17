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
	rm -rf /usr/lib/HTTPCore14.so 
  ;;
  static)
  	echo starting static build...
	g++  -DLINUX  -D_ZLIB_SUPPORT_  -lpthread -lssl -lz HTTPCoreClass/*.cpp HTTPCoreClass/Authentication/*.cpp HTTPCoreClass/Modules/*.cpp Scanner/*.cpp Scanner/Input/*.cpp Scanner/Reporting/*.cpp -o release/Fhscan
  ;;
  debug)
        echo starting static build...
        g++  -ggdb -g3 -O0 -fno-inline  -DLINUX   -lpthread  HTTPCoreClass/*.cpp HTTPCoreClass/Authentication/*.cpp HTTPCoreClass/Modules/*.cpp Scanner/*.cpp Scanner/Input/*.cpp Scanner/Reporting/*.cpp -o release/Fhscan

  ;;
  dynamic)
	# Make sure that you are root
        if [ "$(id -u)" != "0" ]; then
           echo "This script must be run as root. Try static build instead"
           exit 1
        fi
	echo "Starting dynamic build..."
	g++  -DLINUX  -D_ZLIB_SUPPORT_  -c -fPIC HTTPCoreClass/*.cpp HTTPCoreClass/Authentication/*.cpp HTTPCoreClass/Modules/*.cpp
	g++ -shared -o HTTPCore14.so -fPIC *.o
	cp HTTPCore14.so /usr/lib/libHTTPCore.so
	ln -s /
	g++  -lpthread -lssl -lz -lHTTPCore -DLINUX -D_ZLIB_SUPPORT_ Scanner/*.cpp Scanner/Input/*.cpp Scanner/Reporting/*.cpp -o release/Fhscan
	rm -rf *.o
	;;
  *)
    echo "FHscan v1.4 Build script"
    echo "Usage: ./build.sh  {debug|static|dynamic|clean}"
    echo "       *NOTE* dynamic build will add HTTPCore.so to /usr/lib so you require root privileges."
    exit 1
    ;;
esac

exit 0


