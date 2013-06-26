#---------------------------------------------------------
# steps to build the Incore utility 
#---------------------------------------------------------

# move to Source dir
cd Source

# delete old artifacts
rm -Rf openssl-fips-2.0.1/

# unpack fresh files
tar xzf openssl-fips-2.0.1.tar 
tar xzf ios-incore-2.0.1.tar

# setup environment
. ./setenv-reset.sh
. ./setenv-darwin-i386.sh

# verify paths set by darwin script
env

# move to fips' dir
cd openssl-fips-2.0.1

# configure and make
./config
make

# move to incore's dir and make
cd iOS/
make

# install /usr/local/bin
mkdir /usr/local/bin &> /dev/null
cp ./incore_macho /usr/local/bin
