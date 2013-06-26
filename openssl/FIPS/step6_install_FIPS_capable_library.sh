#---------------------------------------------------------
# install FIPS Capable library
#---------------------------------------------------------

# move to Source dir
cd Source

# move to ssl' dir
cd openssl-1.0.1c/

# setup environment
. ../setenv-reset.sh
. ../setenv-ios-11.sh

FIPSDIR=/usr/local/ssl/Release-iphoneos
INCDIR=/usr/local/ssl/Release-iphoneos/include/openssl

# install - may require root...
# libraries
cp libssl.a $FIPSDIR
cp libcrypto.a $FIPSDIR
ln -s $FIPSDIR/libssl.a $FIPSDIR/lib/
ln -s $FIPSDIR/libcrypto.a $FIPSDIR/lib/

# headers
cp crypto/stack/stack.h     $INCDIR
cp crypto/stack/safestack.h $INCDIR
cp crypto/err/err.h         $INCDIR
cp crypto/bio/bio.h         $INCDIR
cp crypto/lhash/lhash.h     $INCDIR
cp crypto/rand/rand.h       $INCDIR
cp crypto/evp/evp.h         $INCDIR
cp crypto/objects/objects.h $INCDIR
cp crypto/objects/obj_mac.h $INCDIR
cp crypto/asn1/asn1.h       $INCDIR

