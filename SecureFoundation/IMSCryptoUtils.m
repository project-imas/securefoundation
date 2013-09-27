//
//  IMSCryptoUtils.m
//  CryptoUtils
//
//  Upated:
//     Gregg Ganley    Sep 2013
//
//  Created on 10/8/12.
//  Copyright (c) 2013 The MITRE Corporation. All rights reserved.
//

#import "SecureFoundation.h"


//**********************
//**********************
//**
//**
int8_t IMSSum(const void *bytes, size_t length) {
    int8_t sum = 0;
    int8_t *values = (int8_t *)bytes;
    for (size_t i = 0; i < length; i++) {
        sum += values[i];
    }
    return sum;
}


//**********************
//**********************
//**
//**
int8_t IMSTwosComplement(int8_t value) {
    return (~value + 1);
}


//**********************
//**********************
//**
//**
int8_t IMSChecksum(NSData *data) {
    int8_t sum = IMSSum([data bytes], [data length]);
    return IMSTwosComplement(sum);
}


//**********************
//**********************
//**
//**
NSData *IMSCryptoUtilsPseudoRandomData(size_t length) {
    if (length) {
        uint8_t *bytes = malloc(length);
        arc4random_buf(bytes, length);
        return [NSData dataWithBytesNoCopy:bytes length:length];
    }
    return nil;
}


//**********************
//**********************
//**
//**
NSString *IMSGenerateRandomString(int num) {
    NSMutableString* string = [NSMutableString stringWithCapacity:num];
    for (int i = 0; i < num; i++) {
        [string appendFormat:@"%C", (unichar)('a' + arc4random_uniform(25))];
    }
    return string;
}


//**********************
//**********************
//**
//**
NSData *IMSCryptoUtilsDeriveKey(NSData *key, size_t length, NSData *salt) {

    if (!(key && length && salt))
        return nil;
    
#ifdef OpenSSL
    /* Initialise the library */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);
    
    uint8_t *derived_key = malloc(length);
    int status = PKCS5_PBKDF2_HMAC_SHA1(
                               [key bytes],
                               [key length],
                               [salt bytes],
                               [salt length],
                               1000, // number of rounds
                               length,
                               derived_key);
    /* Clean up */
    EVP_cleanup();
    ERR_free_strings();
    
    if (status == 1)
#else

    uint8_t *derived_key = malloc(length);
    int status = CCKeyDerivationPBKDF(kCCPBKDF2,
                                          [key bytes],
                                          [key length],
                                          [salt bytes],
                                          [salt length],
                                          kCCPRFHmacAlgSHA256, // pseudo random algorithm
                                          1000, // number of rounds
                                          derived_key,
                                          length);
    if (status == kCCSuccess)

//** OpenSSL
#endif
    {
        return [NSData dataWithBytesNoCopy:derived_key length:length];
    }
    else {
        free(derived_key);
        //NSLog(@"%s: Unable to generate derived key. Error %d", __PRETTY_FUNCTION__, status);
    }
    
    return nil;
}



//**********************
//**********************
//**
//**
void *IMSCryptoUtilsC_EncryptData(u_int8_t *plaintext, int length, u_int8_t *key, int key_len, u_int8_t *iv) {
    
    if (plaintext == 0 || key == 0 || iv == 0)
        return nil;
    
#ifdef OpenSSL
    int   written;
    
    /* Initialise the library */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);
    
    /* Encrypt the plaintext */
    EVP_CIPHER_CTX *ctx;
    
    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        //NSLog(@"%s: Unable to perform encryption. Error 1", __PRETTY_FUNCTION__);
        //ERR_print_errors_fp(stderr);
        return nil;
    }
    
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cfb(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_set_key_length(ctx, key_len);
            
    //** Initialise the encryption operation.
    //** use CFB. cipher feedback, or streaming block cipher mode such that plaintext len = cipher text
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cfb(), NULL, key, iv)) {
        //NSLog(@"%s: Unable to perform encryption. Error 2", __PRETTY_FUNCTION__);
        //ERR_print_errors_fp(stderr);
        return nil;
    }
    
    void *ciphertext = malloc(length);
    if (ciphertext == nil)
        { return nil; }
    
    //** Provide the plaintext to be encrypted, and obtain the encrypted output
    //** set ciphertext pointer past IV
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &written, plaintext, length)) {
        free(ciphertext);
        //NSLog(@"%s: Unable to perform encryption. Error 3", __PRETTY_FUNCTION__);
        //ERR_print_errors_fp(stderr);
        return nil;
    }
    
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    
    if (written != length) {
        free(ciphertext);
        //NSLog(@"%s: Unable to perform encryption. Error 4", __PRETTY_FUNCTION__);
        return nil;
    }
    
    
#if 0
    //** debug
    printf("Ciphertext is:\n");
    BIO_dump_fp(stdout, ciphertext, length);
#endif
    
    /* Clean up */
    EVP_cleanup();
    ERR_free_strings();
    
    return ciphertext;
    
#else
    //*****************************************
    //*****************************************
    //** Apple Crypto
    
    return nil;
#endif
    
}



//**********************
//**********************
//**
//**
void *IMSCryptoUtilsC_DecryptData(u_int8_t *ciphertext, int length, u_int8_t *key, int key_len, u_int8_t *iv)
{
    if (ciphertext == 0 || key == 0 || iv == 0)
        return nil;
    
#ifdef OpenSSL
    /* Initialise the library */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);
    
    int written;
    EVP_CIPHER_CTX *ctx;
    
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        //NSLog(@"%s: Unable to perform decryption. Error 1", __PRETTY_FUNCTION__);
        //ERR_print_errors_fp(stderr);
        return nil;
    }
    
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cfb(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_set_key_length(ctx, key_len);

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cfb(), NULL, key, iv)) {
        //NSLog(@"%s: Unable to perform decryption. Error 2", __PRETTY_FUNCTION__);
        //ERR_print_errors_fp(stderr);
        return nil;
    }
    
    // create buffer
    void *plaintext = malloc(length);
    if (plaintext == nil)
        { return nil; }
    
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &written, ciphertext, length) ) {
        free(plaintext);
        //NSLog(@"%s: Unable to perform decryption. Error 3", __PRETTY_FUNCTION__);
        //ERR_print_errors_fp(stderr);
        return nil;
    }
    
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    
    if (written != length) {
        free(plaintext);
        //NSLog(@"%s: Unable to perform decryption. Error 4", __PRETTY_FUNCTION__);
        return nil;
    }
    
    
    return plaintext;
    
#else
    //*****************************************
    //*****************************************
    //** Apple Crypto
    
    return nil;
#endif
    
}




//**********************
//**********************
//**
//**
NSData *IMSCryptoUtilsSimpleEncryptData(NSData *plaintext, NSData *key, NSData *iv) {
    
    if (plaintext == 0 || key == 0 || iv == 0)
        return nil;

#ifdef OpenSSL
    int   written;
    int length = [plaintext length];
    
    /* Initialise the library */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);
    
    /* Encrypt the plaintext */
    EVP_CIPHER_CTX *ctx;
    
    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        //NSLog(@"%s: Unable to perform encryption. Error 1", __PRETTY_FUNCTION__);
        //ERR_print_errors_fp(stderr);
        return nil;
    }
    
    //** Initialise the encryption operation.
    //** use CFB. cipher feedback, or streaming block cipher mode such that plaintext len = cipher text
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cfb(), NULL, [key bytes], [iv bytes])) {
        //NSLog(@"%s: Unable to perform encryption. Error 2", __PRETTY_FUNCTION__);
        //ERR_print_errors_fp(stderr);
        return nil;
    }
    
    void *ciphertext = malloc(length);
    if (ciphertext == nil)
        { return nil; }
    
    //** Provide the plaintext to be encrypted, and obtain the encrypted output
    //** set ciphertext pointer past IV
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &written, [plaintext bytes], [plaintext length])) {
        free(ciphertext);
        //NSLog(@"%s: Unable to perform encryption. Error 3", __PRETTY_FUNCTION__);
        //ERR_print_errors_fp(stderr);
        return nil;
    }
    
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if (written != length) {
        free(ciphertext);
        //NSLog(@"%s: Unable to perform encryption. Error 4", __PRETTY_FUNCTION__);
        return nil;
    }
    

#if 0
    //** debug
    printf("Ciphertext is:\n");
    BIO_dump_fp(stdout, ciphertext, length);
#endif
    
    /* Clean up */
    EVP_cleanup();
    ERR_free_strings();
    
    return [NSData dataWithBytesNoCopy:ciphertext length:length];
    
#else
    //*****************************************
    //*****************************************
    //** Apple Crypto
    
    return nil;
#endif
    
}



//**********************
//**********************
//**
//**
NSData *IMSCryptoUtilsSimpleDecryptData(NSData *ciphertext, NSData *key, NSData *iv) {
    if (ciphertext == 0 || key == 0 || iv == 0)
        return nil;
    
#ifdef OpenSSL
    /* Initialise the library */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);
    
    int written;
    EVP_CIPHER_CTX *ctx;
    int length = [ciphertext length];
    
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        //NSLog(@"%s: Unable to perform decryption. Error 1", __PRETTY_FUNCTION__);
        //ERR_print_errors_fp(stderr);
        return nil;
    }
    
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cfb(), NULL, [key bytes], [iv bytes])) {
        //NSLog(@"%s: Unable to perform decryption. Error 2", __PRETTY_FUNCTION__);
        //ERR_print_errors_fp(stderr);
        return nil;
    }
    
    // create buffer
    void *plaintext = malloc(length);
    if (plaintext == nil)
        { return nil; }
    
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &written, [ciphertext bytes], length) ) {
        free(plaintext);
        //NSLog(@"%s: Unable to perform decryption. Error 3", __PRETTY_FUNCTION__);
        //ERR_print_errors_fp(stderr);
        return nil;
    }
    
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    
    if (written != length) {
        free(plaintext);
        //NSLog(@"%s: Unable to perform decryption. Error 4", __PRETTY_FUNCTION__);
        return nil;
    }

    
    return [NSData dataWithBytesNoCopy:plaintext length:length];

#else
//*****************************************
//*****************************************
//** Apple Crypto

    return nil;
#endif

}


    
//**********************
//**********************
//**
//**
NSData *IMSCryptoUtilsEncryptData(NSData *plaintext, NSData *key) {
    
    if (plaintext == 0 || key == 0)
        return nil;
    
#ifdef OpenSSL
    // get initialization vector
    NSData *iv_data = IMSCryptoUtilsPseudoRandomData(kCCBlockSizeAES128);
    
    /* Buffer for ciphertext. Ensure the buffer is long enough for the
     * ciphertext which may be longer than the plaintext, dependant on the
     * algorithm and mode
     */
    //** ciphertext:
    //**  ||| IV (16B) | ciphertext | checksum (1B) |||
    //** extra length defined here (16B + plaintext.len + 16B, but that is ok
    size_t ciphertext_len = ([plaintext length] + kCCBlockSizeAES128 + [iv_data length]);
    //** set the running length
    size_t length = [iv_data length];
    int   written;
    
    /* Initialise the library */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);
    
    /* Encrypt the plaintext */
    EVP_CIPHER_CTX *ctx;
    
    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        //NSLog(@"%s: Unable to perform encryption. Error 1", __PRETTY_FUNCTION__);
        //ERR_print_errors_fp(stderr);
        return nil;
    }
    
    //** Initialise the encryption operation.
    //** use CFB. cipher feedback, or streaming block cipher mode such that plaintext = cipher text
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cfb(), NULL, [key bytes], [iv_data bytes])) {
        //NSLog(@"%s: Unable to perform encryption. Error 2", __PRETTY_FUNCTION__);
        //ERR_print_errors_fp(stderr);
        return nil;
    }
    
    void *ciphertext = malloc(ciphertext_len);
    if (ciphertext == nil)
        { return nil; }

    //** ciphertext:
    //**  ||| IV (16B) | ciphertext | checksum (1B) |||
    
    //** copy initialization vector(IV) to start of ciphertext...
    memcpy(ciphertext, [iv_data bytes], [iv_data length]);
    
    //** Provide the plaintext to be encrypted, and obtain the encrypted output
    //** set ciphertext pointer past IV
    if (1 != EVP_EncryptUpdate(ctx, ciphertext + length, &written, [plaintext bytes], [plaintext length])) {
        free(ciphertext);
        //NSLog(@"%s: Unable to perform encryption. Error 3", __PRETTY_FUNCTION__);
        //ERR_print_errors_fp(stderr);
        return nil;
    }
    length += written;
    
    // encrypt plaintext checksum and add to end of ciphertext
    uint8_t checksum = IMSChecksum(plaintext);
    if (1 != EVP_EncryptUpdate(ctx, ciphertext + length, &written, &checksum, sizeof(uint8_t)) ) {
        free(ciphertext);
        //NSLog(@"%s: Unable to perform encryption. Error 3", __PRETTY_FUNCTION__);
        //ERR_print_errors_fp(stderr);
        return nil;
    }
    length += written;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

#if 0
    //** debug
    printf("Ciphertext is:\n");
    BIO_dump_fp(stdout, ciphertext, length);
#endif
    
    /* Clean up */
    EVP_cleanup();
    ERR_free_strings();

    return [NSData dataWithBytesNoCopy:ciphertext length:length];  
    
#else
    //*****************************************
    //*****************************************
    //** Apple Crypto
    
    // get initialization vector
    NSData *iv_data = IMSCryptoUtilsPseudoRandomData(kCCBlockSizeAES128);
        
    // get a cryptor instance
    CCCryptorRef cryptor;
    CCCryptorStatus status = CCCryptorCreate(kCCEncrypt, // operation
                                             kCCAlgorithmAES128, // algorithm
                                             kCCOptionPKCS7Padding, // options
                                             [key bytes], [key length], // key bytes and length
                                             [iv_data bytes], // initialization vector
                                             &cryptor);
    if (status != kCCSuccess)
        { return nil; }
        
    // create a buffer
    size_t ciphertext_len = ([plaintext length] + kCCBlockSizeAES128 + [iv_data length]);
    size_t length = [iv_data length];
    size_t written;
    void *ciphertext = malloc(ciphertext_len);
    if (ciphertext == nil)
        { return nil; }
    
    // set initialization vector, at start of ciphertext...
    memcpy(ciphertext, [iv_data bytes], [iv_data length]);
        
    // encrypt user data, add to pointer after IV data
    status = CCCryptorUpdate(cryptor,
                             [plaintext bytes], [plaintext length],
                             ciphertext + length,
                             ciphertext_len - length,
                             &written);
    if (status != kCCSuccess)
        { return nil; }
    length += written;
        
    // encrypt plaintext checksum
    int8_t checksum = IMSChecksum(plaintext);
    CCCryptorUpdate(cryptor,
                    &checksum, sizeof(int8_t),
                    ciphertext + length,
                    ciphertext_len - length,
                    &written);
    length += written;
        
    // finalize
    status = CCCryptorFinal(cryptor,
                            ciphertext + length,
                            ciphertext_len - length,
                            &written);
    length += written;
        
    // release
    CCCryptorRelease(cryptor);
        
    // cleanup and return
    if (status == kCCSuccess) {
         return [NSData dataWithBytesNoCopy:ciphertext length:length];
    }
    else {
        free(ciphertext);
        //NSLog(@"%s: Unable to perform encryption. Error %d", __PRETTY_FUNCTION__, status);
    }

    return nil;
    
//** end OpenSSL
#endif
    
}


//**********************
//**********************
//**
//**
NSData *IMSCryptoUtilsDecryptData(NSData *ciphertext, NSData *key) {
  if (ciphertext == 0 || key == 0)
    return nil;
  
#ifdef OpenSSL
  /* Initialise the library */
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OPENSSL_config(NULL);
  
  EVP_CIPHER_CTX *ctx;
  int len = 0;
    
  //** ciphertext:
  //**  ||| IV (16B) | ciphertext | checksum (1B) ||||
    
  //** subtract lenght of IV from ciphertext len
  int plaintext_len = [ciphertext length]  -  kCCBlockSizeAES128;
  
  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) {
    //NSLog(@"%s: Unable to perform decryption. Error 1", __PRETTY_FUNCTION__);
    //ERR_print_errors_fp(stderr);
    return nil;
  }
  
  //** Initialise the decryption operation. 
  //** start of cipher text is the IV, 128 bits
  //** get initialization vector at start of ciphertext...
  unsigned char *iv = malloc(kCCBlockSizeAES128);
  if (iv == nil)
    { return nil; }
  memcpy(iv, [ciphertext bytes],  kCCBlockSizeAES128);
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cfb(), NULL, [key bytes], iv)) {
    free(iv);
      //NSLog(@"%s: Unable to perform decryption. Error 2", __PRETTY_FUNCTION__);
    //ERR_print_errors_fp(stderr);
    return nil;
  }
  
  // create buffer
  void *plaintext = malloc(plaintext_len);
  if (plaintext == nil) {
    free(iv);
    return nil;
  }
  
  //** decrypt ciphertext, starting with pointer set to end of IV (16B)
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, 
                            [ciphertext bytes] + kCCBlockSizeAES128, 
                            [ciphertext length] -  kCCBlockSizeAES128) ) {
    //NSLog(@"%s: Unable to perform decryption. Error 3", __PRETTY_FUNCTION__);
    //ERR_print_errors_fp(stderr);
    free(iv);
    free(plaintext);
    return nil;
  }
  
  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  //** ensure the newly decrypted plain text length is same length as ciphertext len (not including IV)
  int8_t sum = IMSSum(plaintext, plaintext_len);
  //** return ciphertext being sure to strip checksum byte from end
  NSData *data = [NSData dataWithBytesNoCopy:plaintext length:plaintext_len - 1];
  if (sum == 0) {
    //** success
    free(iv);
    return data;
  }

  NSLog(@"%s: Integrity check failed.", __PRETTY_FUNCTION__);
  free(iv);
  free(plaintext);
  return nil;

#else
  //*****************************************
  //*****************************************
  //** Apple Crypto
  
  // determine total needed space
  size_t plaintext_len;
  CCCryptorStatus status;
  CCCrypt(kCCDecrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding,
          [key bytes], [key length],
          [ciphertext bytes],
          [ciphertext bytes] + kCCBlockSizeAES128, [ciphertext length] - kCCBlockSizeAES128,
          NULL, 0,
          &plaintext_len);
  
  // create buffer
  void *plaintext = malloc(plaintext_len);
  if (plaintext == nil)
    { return nil; }
  
  // perform decryption
  status = CCCrypt(kCCDecrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding,
                   [key bytes], [key length],
                   [ciphertext bytes],
                   [ciphertext bytes] + kCCBlockSizeAES128, [ciphertext length] - kCCBlockSizeAES128,
                   plaintext, plaintext_len, &plaintext_len);
  
  // cleanup and return
  if (status == kCCSuccess) {
    int8_t sum = IMSSum(plaintext, plaintext_len);
    NSData *data = [NSData dataWithBytesNoCopy:plaintext length:plaintext_len - 1];
    if (sum == 0) {
      //** success
      return data;
    }
    else {
      NSLog(@"%s: Integrity check failed.", __PRETTY_FUNCTION__);
      return nil;
    }
  }
  else {
    free((__bridge void *)(ciphertext));
#ifdef DEBUG
    NSLog(@"%s: Unable to perform encryption. Error %d", __PRETTY_FUNCTION__, status);
#endif
  }
  
//** end OpenSSL
#endif
    
  return nil;
}


//**********************
//**********************
//**
//**
NSData *IMSCryptoUtilsEncryptPlistObject(id object, NSData *key) {
    NSData *data = IMSConvertPlistObjectToData(object);
    return IMSCryptoUtilsEncryptData(data, key);
}


//**********************
//**********************
//**
//**
id IMSCryptoUtilsDecryptPlistObject(NSData *data, NSData *key) {
    NSData *decrypted = IMSCryptoUtilsDecryptData(data, key);
    return IMSConvertDataToPlistObject(decrypted);
}


//**********************
//**********************
//**
//**
NSData *IMSHashData_MD5(NSData *data) {
#ifdef OpenSSL
    EVP_MD_CTX	evp;
    
    void *buffer = malloc(MD5_DIGEST_LENGTH);
    EVP_MD_CTX_init(&evp);
    
    EVP_DigestInit_ex(&evp,EVP_md5(), NULL);
    
    EVP_DigestUpdate(&evp,	[data bytes], [data length]);
    
    EVP_DigestFinal_ex(&evp, buffer,NULL);
    
    EVP_MD_CTX_cleanup(&evp);
    
    return [NSData dataWithBytesNoCopy:buffer length:MD5_DIGEST_LENGTH];
#else
    void *buffer = malloc(CC_MD5_DIGEST_LENGTH);
    CC_MD5([data bytes], [data length], buffer);
    return [NSData dataWithBytesNoCopy:buffer length:CC_MD5_DIGEST_LENGTH];
#endif
    return nil;
}

//**********************
//**********************
//**
//**
unsigned char *IMSHashBytes_MD5(void *obj, int len) {
#ifdef OpenSSL
    EVP_MD_CTX	evp;
    
    void *buffer = malloc(MD5_DIGEST_LENGTH);
    EVP_MD_CTX_init(&evp);
    
    EVP_DigestInit_ex(&evp,EVP_md5(), NULL);
    
    EVP_DigestUpdate(&evp,	obj, len);
    
    EVP_DigestFinal_ex(&evp, buffer, NULL);
    
    EVP_MD_CTX_cleanup(&evp);
    
    return buffer;
    
#else
    void *buffer = malloc(CC_MD5_DIGEST_LENGTH);
    CC_MD5(obj, len, buffer);
    return buffer;
#endif
}


NSData *IMSHashPlistObject_MD5(id object) {
    NSData *data = IMSConvertPlistObjectToData(object);
    return IMSHashData_MD5(data);
}


//**********************
//**********************
//**
//**
NSData *IMSHashData_SHA256(NSData *data) {
#ifdef OpenSSL
    EVP_MD_CTX	evp;
    
    void *buffer = malloc(SHA256_DIGEST_LENGTH);
    EVP_MD_CTX_init(&evp);
    
    EVP_DigestInit_ex(&evp,EVP_sha256(), NULL);
    
    EVP_DigestUpdate(&evp,	[data bytes], [data length]);
    
    EVP_DigestFinal_ex(&evp, buffer,NULL);
    
    EVP_MD_CTX_cleanup(&evp);
        
    return [NSData dataWithBytesNoCopy:buffer length:SHA256_DIGEST_LENGTH];

#else
    void *buffer = malloc(CC_SHA256_DIGEST_LENGTH);
    CC_SHA256([data bytes], [data length], buffer);
    return [NSData dataWithBytesNoCopy:buffer length:CC_SHA256_DIGEST_LENGTH];
#endif
}

//**********************
//**********************
//**
//**
unsigned char *IMSHashBytes_SHA256(void *obj, int len) {
#ifdef OpenSSL
    EVP_MD_CTX	evp;
    
    void *buffer = malloc(SHA256_DIGEST_LENGTH);
    EVP_MD_CTX_init(&evp);
    
    EVP_DigestInit_ex(&evp,EVP_sha256(), NULL);
    
    EVP_DigestUpdate(&evp,	obj, len);
    
    EVP_DigestFinal_ex(&evp, buffer, NULL);
    
    EVP_MD_CTX_cleanup(&evp);
    
    return buffer;
    
#else
    void *buffer = malloc(CC_SHA256_DIGEST_LENGTH);
    CC_SHA256(obj, len, buffer);
    return buffer;
#endif
}

//**********************
//**********************
//**
//**
NSData *IMSHashPlistObject_SHA256(id object) {
    NSData *data = IMSConvertPlistObjectToData(object);
    return IMSHashData_SHA256(data);
}


//**********************
//**********************
//**
//**
NSData *IMSConvertPlistObjectToData(id object) {
    return [NSPropertyListSerialization
            dataWithPropertyList:object
            format:NSPropertyListBinaryFormat_v1_0
            options:0
            error:nil];
}


//**********************
//**********************
//**
//**
id IMSConvertDataToPlistObject(NSData *data) {
    return [NSPropertyListSerialization
            propertyListWithData:data
            options:0
            format:0
            error:nil];
}


/* Example Base64 test code
- (void)testZeroWrapWidth
{
    //set up data
    NSString *inputString = @"Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
    NSData *inputData = [inputString dataUsingEncoding:NSUTF8StringEncoding];
    
    //encode
    NSString *encodedString = [inputData base64EncodedStringWithWrapWidth:0];
    
    //decode
    NSData *outputData = [NSData dataWithBase64EncodedString:encodedString];
    NSString *outputString = [[NSString alloc] initWithData:outputData encoding:NSUTF8StringEncoding];
    NSAssert([outputString isEqualToString:inputString], @"WrappedInput test failed");
}
*/


//****************
//****************
//**
//**
NSString *IMSEncodeBase64(NSData *inputData) {
    //encode
    NSString *encodedString = [Base64 encodeBase64WithData:inputData];

    return encodedString;
}

//****************
//****************
//**
//**
NSData *IMSDeodeBase64(NSString *encodedString) {
    // decode
    NSData *outputData = [Base64 decodeBase64WithString:encodedString];

    return outputData;
}


