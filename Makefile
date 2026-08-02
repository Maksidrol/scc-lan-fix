# Builds systemdetection.dll for 32-bit Wine/Proton
# Requires MinGW: i686-w64-mingw32-gcc
#
# On Ubuntu/Debian:  sudo apt install mingw-w64
# On Arch/SteamOS:   sudo pacman -S mingw-w64-gcc
# On Windows/MSYS2:  pacman -S mingw-w64-i686-gcc

CC = i686-w64-mingw32-gcc

wsock32.dll: wsock32.c wsock32.def
	$(CC) -m32 -shared -O2 \
		-o wsock32.dll \
		wsock32.c wsock32.def \
		-lws2_32 -liphlpapi \
		-Wall -Wno-unused-parameter

clean:
	rm -f wsock32.dll
