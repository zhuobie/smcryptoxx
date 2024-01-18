# Introduction

 A C++ implementation of China's standards of encryption algorithms(SM2/SM3/SM4). 

 # Usage

 This library depends on `libgmpxx` and `libtasn1`. You must first install them, or you can download and build them by yourself.

 - Debian/Ubuntu: 

 ```
 apt install libgmp-dev libgmpxx4ldbl libtasn1-6-dev libtasn1-6
 ```

 - Fedora

 ```
 dnf install gmp-devel gmp-c++ libtasn1 libtasn1-devel
 ```

 - FreeBSD

 ```
 pkg install gmp libtasn1
 ```

 - Windows

 In MSYS2:

 ```
 pacman -S gcc make cmake gmp-devel libtasn1-devel
 ```

 In Cygwin: Install `gcc-g++ make cmake libgmp-devel libtasn1-devel`

 Then build this lib:

 ```
 cd smcryptoxx
 mkdir build
 cd build
 cmake ..
 make
 make install
 make test
 ```

 # Examples

 See `tests` directory.
 