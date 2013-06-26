#
# setenv-i386.sh
#


SYSTEM="darwin"
MACHINE="i386"

SYSTEM="Darwin"
MACHINE="i386"
KERNEL_BITS=32

export MACHINE
export SYSTEM
export KERNEL_BITS

# adjust the path to ensure we always get the correct tools
export PATH="`pwd`"/iOS:$PATH
