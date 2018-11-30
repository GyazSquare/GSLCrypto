//
//  NSDataGSLCryptoAdditions.h
//  GSLCrypto
//

#include <CommonCrypto/CommonCrypto.h>

@import Foundation.NSData;

NS_ASSUME_NONNULL_BEGIN

@interface NSData (GSLDigest)

- (NSData *)gsl_MD2Digest;
- (NSData *)gsl_MD4Digest;
- (NSData *)gsl_MD5Digest;

- (NSData *)gsl_SHA1Digest;
- (NSData *)gsl_SHA224Digest;
- (NSData *)gsl_SHA256Digest;
- (NSData *)gsl_SHA384Digest;
- (NSData *)gsl_SHA512Digest;

@end

typedef NS_ENUM(NSUInteger, GSLHMACAlgorithm) {
    GSLHMACAlgorithmSHA1 = kCCHmacAlgSHA1,
    GSLHMACAlgorithmMD5 = kCCHmacAlgMD5,
    GSLHMACAlgorithmSHA256 = kCCHmacAlgSHA256,
    GSLHMACAlgorithmSHA384 = kCCHmacAlgSHA384,
    GSLHMACAlgorithmSHA512 = kCCHmacAlgSHA512,
    GSLHMACAlgorithmSHA224 = kCCHmacAlgSHA224
};

@interface NSData (GSLHMAC)

- (NSData *)gsl_HMACUsingAlgorithm:(GSLHMACAlgorithm)algorithm key:(NSData *)key;

@end

typedef NS_ENUM(NSInteger, GSLCryptoAlgorithm) {
    GSLCryptoAlgorithmAES = kCCAlgorithmAES,
    GSLCryptoAlgorithmDES = kCCAlgorithmDES,
    GSLCryptoAlgorithm3DES = kCCAlgorithm3DES,
    GSLCryptoAlgorithmCAST = kCCAlgorithmCAST,
    GSLCryptoAlgorithmRC4 = kCCAlgorithmRC4,
    GSLCryptoAlgorithmRC2 = kCCAlgorithmRC2,
    GSLCryptoAlgorithmBlowfish = kCCAlgorithmBlowfish
};

typedef NS_OPTIONS(NSUInteger, GSLCryptoOptions) {
    GSLCryptoOptionPKCS7Padding = kCCOptionPKCS7Padding,
    GSLCryptoOptionECBMode = kCCOptionECBMode
};

@interface NSData (GSLCrypto)

- (nullable NSData *)gsl_encryptedDataUsingAlgorithm:(GSLCryptoAlgorithm)algorithm options:(GSLCryptoOptions)options key:(nullable NSData *)key initializationVector:(nullable NSData *)initializationVector error:(NSError **)error;
- (nullable NSData *)gsl_decryptedDataUsingAlgorithm:(GSLCryptoAlgorithm)algorithm options:(GSLCryptoOptions)options key:(nullable NSData *)key initializationVector:(nullable NSData *)initializationVector error:(NSError **)error;

@end

FOUNDATION_EXPORT NSString * const GSLCryptoErrorDomain;

typedef NS_ENUM(NSInteger, GSLCryptoError) {
    GSLCryptoErrorSuccess = kCCSuccess,
    GSLCryptoErrorParamError = kCCParamError,
    GSLCryptoErrorBufferTooSmall = kCCBufferTooSmall,
    GSLCryptoErrorMemoryFailure = kCCMemoryFailure,
    GSLCryptoErrorAlignmentError = kCCAlignmentError,
    GSLCryptoErrorDecodeError = kCCDecodeError,
    GSLCryptoErrorUnimplemented = kCCUnimplemented,
    GSLCryptoErrorOverflow = kCCOverflow,
    GSLCryptoErrorRNGFailure = kCCRNGFailure
};

NS_ASSUME_NONNULL_END
