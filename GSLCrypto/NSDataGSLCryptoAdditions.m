//
//  NSDataGSLCryptoAdditions.m
//  GSLCrypto
//

@import Foundation;

#import "NSDataGSLCryptoAdditions.h"

NSString * const GSLCryptoErrorDomain = @"GSLCryptoErrorDomain";

static NSError * __GSLErrorWithCryptoStatus(CCCryptorStatus status) {
    NSString *localizedDescription;
    switch (status) {
        case kCCSuccess:
            return nil;
        case kCCParamError:
            localizedDescription = @"Illegal parameter value.";
            break;
        case kCCBufferTooSmall:
            localizedDescription = @"Insufficent buffer provided for specified operation.";
            break;
        case kCCMemoryFailure:
            localizedDescription = @"Memory allocation failure.";
            break;
        case kCCAlignmentError:
            localizedDescription = @"Input size was not aligned properly.";
            break;
        case kCCDecodeError:
            localizedDescription = @"Input data did not decode or decrypt properly.";
            break;
        case kCCUnimplemented:
            localizedDescription = @"Function not implemented for the current algorithm.";
            break;
        default:
            break;
    }
    NSDictionary *userInfo = localizedDescription ? @{NSLocalizedDescriptionKey: localizedDescription} : nil;
    return [NSError errorWithDomain:GSLCryptoErrorDomain code:status userInfo:userInfo];
}

@implementation NSData (GSLDigest)

- (NSData *)gsl_MD2Digest {
    unsigned char md[CC_MD2_DIGEST_LENGTH];
    CC_MD2(self.bytes, (CC_LONG)self.length, md);
    return [NSData dataWithBytes:md length:CC_MD2_DIGEST_LENGTH];
}

- (NSData *)gsl_MD4Digest {
    unsigned char md[CC_MD4_DIGEST_LENGTH];
    CC_MD4(self.bytes, (CC_LONG)self.length, md);
    return [NSData dataWithBytes:md length:CC_MD4_DIGEST_LENGTH];
}

- (NSData *)gsl_MD5Digest {
    unsigned char md[CC_MD5_DIGEST_LENGTH];
    CC_MD5(self.bytes, (CC_LONG)self.length, md);
    return [NSData dataWithBytes:md length:CC_MD5_DIGEST_LENGTH];
}

- (NSData *)gsl_SHA1Digest {
    unsigned char md[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(self.bytes, (CC_LONG)self.length, md);
    return [NSData dataWithBytes:md length:CC_SHA1_DIGEST_LENGTH];
}

- (NSData *)gsl_SHA224Digest {
    unsigned char md[CC_SHA224_DIGEST_LENGTH];
    CC_SHA224(self.bytes, (CC_LONG)self.length, md);
    return [NSData dataWithBytes:md length:CC_SHA224_DIGEST_LENGTH];
}

- (NSData *)gsl_SHA256Digest {
    unsigned char md[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(self.bytes, (CC_LONG)self.length, md);
    return [NSData dataWithBytes:md length:CC_SHA256_DIGEST_LENGTH];
}

- (NSData *)gsl_SHA384Digest {
    unsigned char md[CC_SHA384_DIGEST_LENGTH];
    CC_SHA384(self.bytes, (CC_LONG)self.length, md);
    return [NSData dataWithBytes:md length:CC_SHA384_DIGEST_LENGTH];
}

- (NSData *)gsl_SHA512Digest {
    unsigned char md[CC_SHA512_DIGEST_LENGTH];
    CC_SHA512(self.bytes, (CC_LONG)self.length, md);
    return [NSData dataWithBytes:md length:CC_SHA512_DIGEST_LENGTH];
}

@end

@implementation NSData (GSLHMAC)

- (NSData *)gsl_HMACUsingAlgorithm:(GSLHMACAlgorithm)algorithm key:(NSData *)key {
    size_t length;
    switch (algorithm) {
        case GSLHMACAlgorithmSHA1:
            length = CC_SHA1_DIGEST_LENGTH;
            break;
        case GSLHMACAlgorithmMD5:
            length = CC_MD5_DIGEST_LENGTH;
            break;
        case GSLHMACAlgorithmSHA256:
            length = CC_SHA256_DIGEST_LENGTH;
            break;
        case GSLHMACAlgorithmSHA384:
            length = CC_SHA384_DIGEST_LENGTH;
            break;
        case GSLHMACAlgorithmSHA512:
            length = CC_SHA512_DIGEST_LENGTH;
            break;
        case GSLHMACAlgorithmSHA224:
            length = CC_SHA224_DIGEST_LENGTH;
            break;
    }
    unsigned char data[length];
    CCHmac((CCHmacAlgorithm)algorithm, key.bytes, key.length, self.bytes, self.length, data);
    return [NSData dataWithBytes:data length:length];
}

@end

@implementation NSData (GSLCrypto)

- (nullable NSData *)gsl_encryptedDataUsingAlgorithm:(GSLCryptoAlgorithm)algorithm options:(GSLCryptoOptions)options key:(nullable NSData *)key initializationVector:(nullable NSData *)initializationVector error:(NSError **)error {
    return [self gsl_cryptedDataWithOperation:kCCEncrypt usingAlgorithm:algorithm options:options key:key initializationVector:initializationVector error:error];
}

- (nullable NSData *)gsl_decryptedDataUsingAlgorithm:(GSLCryptoAlgorithm)algorithm options:(GSLCryptoOptions)options key:(nullable NSData *)key initializationVector:(nullable NSData *)initializationVector error:(NSError **)error {
    return [self gsl_cryptedDataWithOperation:kCCDecrypt usingAlgorithm:algorithm options:options key:key initializationVector:initializationVector error:error];
}

#pragma mark - Class extensions

- (nullable NSData *)gsl_cryptedDataWithOperation:(CCOperation)operation usingAlgorithm:(GSLCryptoAlgorithm)algorithm options:(GSLCryptoOptions)options key:(nullable NSData *)key initializationVector:(nullable NSData *)initializationVector error:(NSError * __autoreleasing *)error {
    __block NSData *cryptedData = nil;
    __block CCCryptorRef cryptor = NULL;
    __block CCCryptorStatus status = kCCSuccess;
    NSData * (^finallyBlock)(void) = ^ NSData * {
        if (cryptor) {
            CCCryptorRelease(cryptor);
        }
        if (status != kCCSuccess) {
            if (error) {
                *error = __GSLErrorWithCryptoStatus(status);
            }
            return nil;
        }
        return cryptedData;
    };
    status = CCCryptorCreate(operation, (CCAlgorithm)algorithm, (CCOptions)options, key.bytes, key.length, initializationVector.bytes, &cryptor);
    if (status != kCCSuccess) {
        return finallyBlock();
    }
    const void *dataIn = self.bytes;
    size_t dataInLength = self.length;
    size_t dataOutLength = CCCryptorGetOutputLength(cryptor, self.length, true);
    NSMutableData *data = [NSMutableData dataWithLength:dataOutLength];
    void *dataOut = data.mutableBytes;
    size_t dataOutAvailable = dataOutLength;
    size_t dataOutMoved;
    status = CCCryptorUpdate(cryptor, dataIn, dataInLength, dataOut, dataOutAvailable, &dataOutMoved);
    if (status != kCCSuccess) {
        return finallyBlock();
    }
    dataOutLength = dataOutMoved;
    dataOut += dataOutMoved;
    dataOutAvailable -= dataOutMoved;
    status = CCCryptorFinal(cryptor, dataOut, dataOutAvailable, &dataOutMoved);
    if (status != kCCSuccess) {
        return finallyBlock();
    }
    dataOutLength += dataOutMoved;
    data.length = dataOutLength;
    cryptedData = data;
    return finallyBlock();
}

@end
