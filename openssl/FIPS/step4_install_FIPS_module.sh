#---------------------------------------------------------
# install FIPS Object Module
#
# /usr/local/ssl/Release-iphoneos/
#---------------------------------------------------------

# move to Source dir
cd Source

# move to fips' dir
cd openssl-fips-2.0.1

# install - may require root...
make install

# delete artifacts
rm -Rf openssl-fips-2.0.1/
