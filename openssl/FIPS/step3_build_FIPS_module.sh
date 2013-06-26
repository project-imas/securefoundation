#---------------------------------------------------------
# build FIPS Object Module
#---------------------------------------------------------

# move to Source dir
cd Source

# delete old artifacts
rm -Rf openssl-fips-2.0.1/

# make incore_macho available to build
export PATH="/usr/local/bin":$PATH

# unpack fresh files
tar xzf openssl-fips-2.0.1.tar 
tar xzf ios-incore-2.0.1.tar

# move to fips' dir
cd openssl-fips-2.0.1

# setup environment
. ../setenv-reset.sh
. ../setenv-ios-11.sh

# configure and make
./config
make


