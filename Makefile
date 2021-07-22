CC_X64	:= x86_64-w64-mingw32-gcc
CC_X86	:= i686-w64-mingw32-gcc

CFLAGS	:= $(CFLAGS) -Os -fno-asynchronous-unwind-tables -nostdlib 
CFLAGS 	:= $(CFLAGS) -fno-ident -fpack-struct=8 -falign-functions=1
CFLAGS  := $(CFLAGS) -s -ffunction-sections -falign-jumps=1
CFLAGS	:= $(CFLAGS) -falign-labels=1 -fPIC
LFLAGS	:= $(LFLAGS) -Wl,-s,--no-seh,--enable-stdcall-fixup,-Tscripts/LinkOrder.ld

OUTX64	:= NetNtLmCapture.x64.exe
OUTX86	:= NetNtLmCapture.x86.exe
BINX64	:= NetNtLmCapture.x64.bin
BINX86	:= NetNtLmCapture.x86.bin

all:
	@ nasm -f win32 asm/x86/start.asm -o start.x86.o
	@ nasm -f win64 asm/x64/start.asm -o start.x64.o
	@ $(CC_X86) *.c start.x86.o -o $(OUTX86) $(CFLAGS) $(LFLAGS)
	@ $(CC_X64) *.c start.x64.o -o $(OUTX64) $(CFLAGS) $(LFLAGS)
	@ python3 scripts/ExtractBin.py -f $(OUTX86) -o $(BINX86)
	@ python3 scripts/ExtractBin.py -f $(OUTX64) -o $(BINX64)
	@ nasm -f win32 template/NetNtLmCaptureStart.asm -o NetNtLmCaptureStart.x86.o
	@ nasm -f win64 template/NetNtLmCaptureStart.asm -o NetNtLmCaptureStart.x64.o
	@ $(CC_X86) template/NetNtLmCaptureBof.c -c -o NetNtLmCaptureBof.x86.o -Os -s -Qn
	@ $(CC_X64) template/NetNtLmCaptureBof.c -c -o NetNtLmCaptureBof.x64.o -Os -s -Qn
	@ i686-w64-mingw32-ld -r NetNtLmCaptureBof.x86.o NetNtLmCaptureStart.x86.o -o NetNtLmCaptureCs.x86.o --enable-stdcall-fixup
	@ x86_64-w64-mingw32-ld -r NetNtLmCaptureBof.x64.o NetNtLmCaptureStart.x64.o -o NetNtLmCaptureCs.x64.o --enable-stdcall-fixup

clean:
	@ rm -rf *.o
	@ rm -rf *.bin
	@ rm -rf *.exe
