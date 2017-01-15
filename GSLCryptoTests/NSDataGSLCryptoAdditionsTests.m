//
//  NSDataGSLCryptoAdditionsTests.m
//  GSLCrypto
//

@import XCTest;

#import "NSDataGSLCryptoAdditions.h"

@interface NSDataGSLCryptoAdditionsTests : XCTestCase
@end

@implementation NSDataGSLCryptoAdditionsTests

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)test_gsl_digest {
    // MD2
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *digest = [data gsl_MD2Digest];
        const void *bytes = "\x03\xd8\x5a\x0d\x62\x9d\x2c\x44\x2e\x98\x75\x25\x31\x9f\xc4\x71";
        NSData *expected = [NSData dataWithBytes:bytes length:strlen(bytes)];
        XCTAssertEqualObjects(expected, digest);
    }
    // MD4
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *digest = [data gsl_MD4Digest];
        const void *bytes = "\x1b\xee\x69\xa4\x6b\xa8\x11\x18\x5c\x19\x47\x62\xab\xae\xae\x90";
        NSData *expected = [NSData dataWithBytes:bytes length:strlen(bytes)];
        XCTAssertEqualObjects(expected, digest);
    }
    // MD5
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *digest = [data gsl_MD5Digest];
        const void *bytes = "\x9e\x10\x7d\x9d\x37\x2b\xb6\x82\x6b\xd8\x1d\x35\x42\xa4\x19\xd6";
        NSData *expected = [NSData dataWithBytes:bytes length:strlen(bytes)];
        XCTAssertEqualObjects(expected, digest);
    }
    // SHA1
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *digest = [data gsl_SHA1Digest];
        const void *bytes = "\x2f\xd4\xe1\xc6\x7a\x2d\x28\xfc\xed\x84\x9e\xe1\xbb\x76\xe7\x39\x1b\x93\xeb\x12";
        NSData *expected = [NSData dataWithBytes:bytes length:strlen(bytes)];
        XCTAssertEqualObjects(expected, digest);
    }
    // SHA224
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *digest = [data gsl_SHA224Digest];
        const void *bytes = "\x73\x0e\x10\x9b\xd7\xa8\xa3\x2b\x1c\xb9\xd9\xa0\x9a\xa2\x32\x5d\x24\x30\x58\x7d\xdb\xc0\xc3\x8b\xad\x91\x15\x25";
        NSData *expected = [NSData dataWithBytes:bytes length:strlen(bytes)];
        XCTAssertEqualObjects(expected, digest);
    }
    // SHA256
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *digest = [data gsl_SHA256Digest];
        const void *bytes = "\xd7\xa8\xfb\xb3\x07\xd7\x80\x94\x69\xca\x9a\xbc\xb0\x08\x2e\x4f\x8d\x56\x51\xe4\x6d\x3c\xdb\x76\x2d\x02\xd0\xbf\x37\xc9\xe5\x92";
        NSData *expected = [NSData dataWithBytes:bytes length:strlen(bytes)];
        XCTAssertEqualObjects(expected, digest);
    }
    // SHA384
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *digest = [data gsl_SHA384Digest];
        const void *bytes = "\xca\x73\x7f\x10\x14\xa4\x8f\x4c\x0b\x6d\xd4\x3c\xb1\x77\xb0\xaf\xd9\xe5\x16\x93\x67\x54\x4c\x49\x40\x11\xe3\x31\x7d\xbf\x9a\x50\x9c\xb1\xe5\xdc\x1e\x85\xa9\x41\xbb\xee\x3d\x7f\x2a\xfb\xc9\xb1";
        NSData *expected = [NSData dataWithBytes:bytes length:strlen(bytes)];
        XCTAssertEqualObjects(expected, digest);
    }
    // SHA512
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *digest = [data gsl_SHA512Digest];
        const void *bytes = "\x07\xe5\x47\xd9\x58\x6f\x6a\x73\xf7\x3f\xba\xc0\x43\x5e\xd7\x69\x51\x21\x8f\xb7\xd0\xc8\xd7\x88\xa3\x09\xd7\x85\x43\x6b\xbb\x64\x2e\x93\xa2\x52\xa9\x54\xf2\x39\x12\x54\x7d\x1e\x8a\x3b\x5e\xd6\xe1\xbf\xd7\x09\x78\x21\x23\x3f\xa0\x53\x8f\x3d\xb8\x54\xfe\xe6";
        NSData *expected = [NSData dataWithBytes:bytes length:strlen(bytes)];
        XCTAssertEqualObjects(expected, digest);
    }
}

- (void)test_gsl_HMAC {
    // SHA1
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *key = [@"password" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *digest = [data gsl_HMACUsingAlgorithm:GSLHMACAlgorithmSHA1 key:key];
        const void *bytes = "\xac\x20\x07\x1d\x3c\xb2\x62\x6f\xe2\xee\xb5\x9e\x75\xa7\xf8\xd0\x50\x69\x86\x20";
        NSData *expected = [NSData dataWithBytes:bytes length:strlen(bytes)];
        XCTAssertEqualObjects(expected, digest);
    }
    // MD5
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *key = [@"password" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *digest = [data gsl_HMACUsingAlgorithm:GSLHMACAlgorithmMD5 key:key];
        const void *bytes = "\x3f\xbd\xfb\x7c\x9d\x80\x71\xd9\x04\x81\x6c\x25\xfc\xaa\x8b\x94";
        NSData *expected = [NSData dataWithBytes:bytes length:strlen(bytes)];
        XCTAssertEqualObjects(expected, digest);
    }
    // SHA256
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *key = [@"password" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *digest = [data gsl_HMACUsingAlgorithm:GSLHMACAlgorithmSHA256 key:key];
        const void *bytes = "\xf8\xa6\x91\x70\x3d\x51\x56\x69\xc0\x3f\xe5\xc1\x65\x19\xc7\x9a\xc2\x7a\xd2\xe4\xdd\xdc\xba\xd6\xa8\x8f\x10\x15\xe2\xa7\x56\xf7";
        NSData *expected = [NSData dataWithBytes:bytes length:strlen(bytes)];
        XCTAssertEqualObjects(expected, digest);
    }
    // SHA384
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *key = [@"password" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *digest = [data gsl_HMACUsingAlgorithm:GSLHMACAlgorithmSHA384 key:key];
        const void *bytes = "\xe0\xb6\x0f\x66\x51\x2e\x3e\xb9\x31\x52\x6d\xba\x8e\xbf\x87\x62\x29\x64\x0f\x19\xf8\xe0\x7d\x94\x7a\x51\xe6\xa8\x36\xb2\x25\x7a\x51\x37\xcf\x6b\x9d\xd8\x6b\x93\x94\xc5\x4a\x26\x84\x50\x90\x68";
        NSData *expected = [NSData dataWithBytes:bytes length:strlen(bytes)];
        XCTAssertEqualObjects(expected, digest);
    }
    // SHA512
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *key = [@"password" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *digest = [data gsl_HMACUsingAlgorithm:GSLHMACAlgorithmSHA512 key:key];
        const void *bytes = "\xda\x67\xc9\x52\xe7\xfc\x57\x47\xa1\xe9\xc5\x14\x45\xd4\x56\xb4\x11\x5b\xce\x09\x0a\x0c\xe2\x22\x0c\x1b\x63\x4b\x8e\x92\x42\x48\x7b\xe7\x53\xdb\xf6\xd8\x31\x49\x1b\xfa\x03\x06\xdf\xaf\x60\x1c\xe7\x36\x27\x74\xca\xdb\xfd\x3f\x8e\x69\xee\xe5\x32\x31\x2e\x57";
        NSData *expected = [NSData dataWithBytes:bytes length:strlen(bytes)];
        XCTAssertEqualObjects(expected, digest);
    }
    // SHA224
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *key = [@"password" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *digest = [data gsl_HMACUsingAlgorithm:GSLHMACAlgorithmSHA224 key:key];
        const void *bytes = "\x84\x49\x57\x05\x52\x4e\x17\x38\xbf\xf2\x0d\x7b\x41\x9c\x98\x96\x1e\x89\x4d\xfa\x37\xf1\xd2\xe7\xd1\x49\x01\xb3";
        NSData *expected = [NSData dataWithBytes:bytes length:strlen(bytes)];
        XCTAssertEqualObjects(expected, digest);
    }
}

- (void)test_gsl_crypto {
    // param error
    {
        NSData *key = nil;
        NSData *iv = nil;
        NSError *error = nil;
        NSData *encryptedData = [[NSData data] gsl_encryptedDataUsingAlgorithm:GSLCryptoAlgorithmAES options:0 key:key initializationVector:iv error:&error];
        XCTAssertNil(encryptedData);
        XCTAssertNotNil(error);
    }
    // AES128, ECB
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSLCryptoOptions options = (GSLCryptoOptionPKCS7Padding | GSLCryptoOptionECBMode);
        NSData *key = [@"passwordpassword" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = nil;
        NSError *error = nil;
        NSData *encryptedData = [data gsl_encryptedDataUsingAlgorithm:GSLCryptoAlgorithmAES options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gsl_decryptedDataUsingAlgorithm:GSLCryptoAlgorithmAES options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // AES128, CBC
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSLCryptoOptions options = GSLCryptoOptionPKCS7Padding;
        NSData *key = [@"passwordpassword" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = [@"passwordpassword" dataUsingEncoding:NSUTF8StringEncoding];
        NSError *error = nil;
        NSData *encryptedData = [data gsl_encryptedDataUsingAlgorithm:GSLCryptoAlgorithmAES options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gsl_decryptedDataUsingAlgorithm:GSLCryptoAlgorithmAES options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // AES192, ECB
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSLCryptoOptions options = (GSLCryptoOptionPKCS7Padding | GSLCryptoOptionECBMode);
        NSData *key = [@"passwordpasswordpassword" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = nil;
        NSError *error = nil;
        NSData *encryptedData = [data gsl_encryptedDataUsingAlgorithm:GSLCryptoAlgorithmAES options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gsl_decryptedDataUsingAlgorithm:GSLCryptoAlgorithmAES options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // AES192, CBC
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSLCryptoOptions options = GSLCryptoOptionPKCS7Padding;
        NSData *key = [@"passwordpasswordpassword" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = [@"passwordpassword" dataUsingEncoding:NSUTF8StringEncoding];
        NSError *error = nil;
        NSData *encryptedData = [data gsl_encryptedDataUsingAlgorithm:GSLCryptoAlgorithmAES options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gsl_decryptedDataUsingAlgorithm:GSLCryptoAlgorithmAES options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // AES256, ECB
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSLCryptoOptions options = (GSLCryptoOptionPKCS7Padding | GSLCryptoOptionECBMode);
        NSData *key = [@"passwordpasswordpasswordpassword" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = nil;
        NSError *error = nil;
        NSData *encryptedData = [data gsl_encryptedDataUsingAlgorithm:GSLCryptoAlgorithmAES options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gsl_decryptedDataUsingAlgorithm:GSLCryptoAlgorithmAES options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // AES256, CBC
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSLCryptoOptions options = GSLCryptoOptionPKCS7Padding;
        NSData *key = [@"passwordpasswordpasswordpassword" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = [@"passwordpassword" dataUsingEncoding:NSUTF8StringEncoding];
        NSError *error = nil;
        NSData *encryptedData = [data gsl_encryptedDataUsingAlgorithm:GSLCryptoAlgorithmAES options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gsl_decryptedDataUsingAlgorithm:GSLCryptoAlgorithmAES options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // DES, ECB
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSLCryptoOptions options = (GSLCryptoOptionPKCS7Padding | GSLCryptoOptionECBMode);
        NSData *key = [@"password" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = nil;
        NSError *error = nil;
        NSData *encryptedData = [data gsl_encryptedDataUsingAlgorithm:GSLCryptoAlgorithmDES options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gsl_decryptedDataUsingAlgorithm:GSLCryptoAlgorithmDES options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // DES, CBC
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSLCryptoOptions options = GSLCryptoOptionPKCS7Padding;
        NSData *key = [@"password" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = [@"password" dataUsingEncoding:NSUTF8StringEncoding];
        NSError *error = nil;
        NSData *encryptedData = [data gsl_encryptedDataUsingAlgorithm:GSLCryptoAlgorithmDES options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gsl_decryptedDataUsingAlgorithm:GSLCryptoAlgorithmDES options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // 3DES, ECB
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSLCryptoOptions options = (GSLCryptoOptionPKCS7Padding | GSLCryptoOptionECBMode);
        NSData *key = [@"passwordpasswordpassword" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = nil;
        NSError *error = nil;
        NSData *encryptedData = [data gsl_encryptedDataUsingAlgorithm:GSLCryptoAlgorithm3DES options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gsl_decryptedDataUsingAlgorithm:GSLCryptoAlgorithm3DES options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // 3DES, CBC
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSLCryptoOptions options = GSLCryptoOptionPKCS7Padding;
        NSData *key = [@"passwordpasswordpassword" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = [@"password" dataUsingEncoding:NSUTF8StringEncoding];
        NSError *error = nil;
        NSData *encryptedData = [data gsl_encryptedDataUsingAlgorithm:GSLCryptoAlgorithm3DES options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gsl_decryptedDataUsingAlgorithm:GSLCryptoAlgorithm3DES options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // CAST (MIN), ECB
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSLCryptoOptions options = (GSLCryptoOptionPKCS7Padding | GSLCryptoOptionECBMode);
        NSData *key = [@"passw" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = nil;
        NSError *error = nil;
        NSData *encryptedData = [data gsl_encryptedDataUsingAlgorithm:GSLCryptoAlgorithmCAST options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gsl_decryptedDataUsingAlgorithm:GSLCryptoAlgorithmCAST options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // CAST (MIN), CBC
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSLCryptoOptions options = GSLCryptoOptionPKCS7Padding;
        NSData *key = [@"passw" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = [@"password" dataUsingEncoding:NSUTF8StringEncoding];
        NSError *error = nil;
        NSData *encryptedData = [data gsl_encryptedDataUsingAlgorithm:GSLCryptoAlgorithmCAST options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gsl_decryptedDataUsingAlgorithm:GSLCryptoAlgorithmCAST options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // CAST (MAX), ECB
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSLCryptoOptions options = (GSLCryptoOptionPKCS7Padding | GSLCryptoOptionECBMode);
        NSData *key = [@"passwordpassword" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = nil;
        NSError *error = nil;
        NSData *encryptedData = [data gsl_encryptedDataUsingAlgorithm:GSLCryptoAlgorithmCAST options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gsl_decryptedDataUsingAlgorithm:GSLCryptoAlgorithmCAST options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // CAST (MAX), CBC
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSLCryptoOptions options = GSLCryptoOptionPKCS7Padding;
        NSData *key = [@"passwordpassword" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = [@"password" dataUsingEncoding:NSUTF8StringEncoding];
        NSError *error = nil;
        NSData *encryptedData = [data gsl_encryptedDataUsingAlgorithm:GSLCryptoAlgorithmCAST options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gsl_decryptedDataUsingAlgorithm:GSLCryptoAlgorithmCAST options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // RC4 (MIN), ECB
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSLCryptoOptions options = (GSLCryptoOptionPKCS7Padding | GSLCryptoOptionECBMode);
        NSData *key = [@"p" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = nil;
        NSError *error = nil;
        NSData *encryptedData = [data gsl_encryptedDataUsingAlgorithm:GSLCryptoAlgorithmRC4 options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gsl_decryptedDataUsingAlgorithm:GSLCryptoAlgorithmRC4 options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // RC4 (MIN), CBC
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSLCryptoOptions options = GSLCryptoOptionPKCS7Padding;
        NSData *key = [@"p" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = [@"password" dataUsingEncoding:NSUTF8StringEncoding];
        NSError *error = nil;
        NSData *encryptedData = [data gsl_encryptedDataUsingAlgorithm:GSLCryptoAlgorithmRC4 options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gsl_decryptedDataUsingAlgorithm:GSLCryptoAlgorithmRC4 options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // RC4 (MAX), ECB
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSLCryptoOptions options = (GSLCryptoOptionPKCS7Padding | GSLCryptoOptionECBMode);
        NSData *key = [@"passwordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpassword" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = nil;
        NSError *error = nil;
        NSData *encryptedData = [data gsl_encryptedDataUsingAlgorithm:GSLCryptoAlgorithmRC4 options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gsl_decryptedDataUsingAlgorithm:GSLCryptoAlgorithmRC4 options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // RC4 (MAX), CBC
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSLCryptoOptions options = GSLCryptoOptionPKCS7Padding;
        NSData *key = [@"passwordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpassword" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = [@"password" dataUsingEncoding:NSUTF8StringEncoding];
        NSError *error = nil;
        NSData *encryptedData = [data gsl_encryptedDataUsingAlgorithm:GSLCryptoAlgorithmRC4 options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gsl_decryptedDataUsingAlgorithm:GSLCryptoAlgorithmRC4 options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // RC2 (MIN), ECB
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSLCryptoOptions options = (GSLCryptoOptionPKCS7Padding | GSLCryptoOptionECBMode);
        NSData *key = [@"p" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = nil;
        NSError *error = nil;
        NSData *encryptedData = [data gsl_encryptedDataUsingAlgorithm:GSLCryptoAlgorithmRC2 options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gsl_decryptedDataUsingAlgorithm:GSLCryptoAlgorithmRC2 options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // RC2 (MIN), CBC
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSLCryptoOptions options = GSLCryptoOptionPKCS7Padding;
        NSData *key = [@"p" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = [@"password" dataUsingEncoding:NSUTF8StringEncoding];
        NSError *error = nil;
        NSData *encryptedData = [data gsl_encryptedDataUsingAlgorithm:GSLCryptoAlgorithmRC2 options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gsl_decryptedDataUsingAlgorithm:GSLCryptoAlgorithmRC2 options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // RC2 (MAX), ECB
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSLCryptoOptions options = (GSLCryptoOptionPKCS7Padding | GSLCryptoOptionECBMode);
        NSData *key = [@"passwordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpassword" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = nil;
        NSError *error = nil;
        NSData *encryptedData = [data gsl_encryptedDataUsingAlgorithm:GSLCryptoAlgorithmRC2 options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gsl_decryptedDataUsingAlgorithm:GSLCryptoAlgorithmRC2 options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // RC2 (MAX), CBC
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSLCryptoOptions options = GSLCryptoOptionPKCS7Padding;
        NSData *key = [@"passwordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpassword" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = [@"password" dataUsingEncoding:NSUTF8StringEncoding];
        NSError *error = nil;
        NSData *encryptedData = [data gsl_encryptedDataUsingAlgorithm:GSLCryptoAlgorithmRC2 options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gsl_decryptedDataUsingAlgorithm:GSLCryptoAlgorithmRC2 options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // Blowfish (MIN), ECB
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSLCryptoOptions options = (GSLCryptoOptionPKCS7Padding | GSLCryptoOptionECBMode);
        NSData *key = [@"password" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = nil;
        NSError *error = nil;
        NSData *encryptedData = [data gsl_encryptedDataUsingAlgorithm:GSLCryptoAlgorithmBlowfish options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gsl_decryptedDataUsingAlgorithm:GSLCryptoAlgorithmBlowfish options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // Blowfish (MIN), CBC
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSLCryptoOptions options = GSLCryptoOptionPKCS7Padding;
        NSData *key = [@"password" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = [@"password" dataUsingEncoding:NSUTF8StringEncoding];
        NSError *error = nil;
        NSData *encryptedData = [data gsl_encryptedDataUsingAlgorithm:GSLCryptoAlgorithmBlowfish options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gsl_decryptedDataUsingAlgorithm:GSLCryptoAlgorithmBlowfish options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // Blowfish (MAX), ECB
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSLCryptoOptions options = (GSLCryptoOptionPKCS7Padding | GSLCryptoOptionECBMode);
        NSData *key = [@"passwordpasswordpasswordpasswordpasswordpasswordpassword" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = nil;
        NSError *error = nil;
        NSData *encryptedData = [data gsl_encryptedDataUsingAlgorithm:GSLCryptoAlgorithmBlowfish options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gsl_decryptedDataUsingAlgorithm:GSLCryptoAlgorithmBlowfish options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
    // Blowfish (MAX), CBC
    {
        NSData *data = [@"The quick brown fox jumps over the lazy dog" dataUsingEncoding:NSUTF8StringEncoding];
        GSLCryptoOptions options = GSLCryptoOptionPKCS7Padding;
        NSData *key = [@"passwordpasswordpasswordpasswordpasswordpasswordpassword" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *iv = [@"password" dataUsingEncoding:NSUTF8StringEncoding];
        NSError *error = nil;
        NSData *encryptedData = [data gsl_encryptedDataUsingAlgorithm:GSLCryptoAlgorithmBlowfish options:options key:key initializationVector:iv error:&error];
        XCTAssertNotNil(encryptedData);
        XCTAssertNil(error);
        NSData *decryptedData = [encryptedData gsl_decryptedDataUsingAlgorithm:GSLCryptoAlgorithmBlowfish options:options key:key initializationVector:iv error:&error];
        XCTAssertEqualObjects(data, decryptedData);
        XCTAssertNil(error);
    }
}

@end
