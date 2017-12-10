

#import "NSString+HR_MD5.h"
#import <CommonCrypto/CommonDigest.h>

@implementation NSString (HR_MD5)

- (NSString *)HR_MD5 {
    if (!self.length) {
        return @"";
    }
    
    const char *cStr = [self UTF8String];
    unsigned char digest[CC_MD5_DIGEST_LENGTH];
    CC_MD5(cStr, (unsigned int)strlen(cStr), digest); // This is the md5 call
    NSMutableString *output = [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    for(int i = 0; i < CC_MD5_DIGEST_LENGTH; i++) {
        [output appendFormat:@"%02x", digest[i]];
    }
    return  output;
}

- (NSString *)HR_FileMD5 {
    if (!self.length) {
        return @"";
    }
    NSString *fileMD5 = (__bridge_transfer NSString *)FileMD5HashCreateWithPath((__bridge CFStringRef)self, 1024 * 8);
    
    NSFileHandle* fh = [NSFileHandle fileHandleForReadingAtPath:self];
    NSData *data = [fh readDataToEndOfFile];
    NSString *content = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    NSLog(@"%@",content);
    if ([content isEqualToString:@"eee\n"]) {
        NSLog(@"n");
    }
    if ([content isEqualToString:@"eee"]) {
        NSLog(@"m");
    }
    
//    NSString *content = [NSString stringWithContentsOfFile:self encoding:NSUTF8StringEncoding error:nil];
    NSString *contentMD5 = [content HR_MD5];
    NSString *contentEnterMD5 = [[NSString stringWithFormat:@"%@\n", content] HR_MD5];
    if ([fileMD5 isEqualToString:contentMD5]) {
        return contentMD5;
    } else if ([fileMD5 isEqualToString:contentEnterMD5]) {
        return contentMD5;
    } else {
        return fileMD5;
    }
}

CFStringRef FileMD5HashCreateWithPath(CFStringRef filePath,size_t chunkSizeForReadingData) {
    // Declare needed variables
    CFStringRef result = NULL;
    CFReadStreamRef readStream = NULL;
    // Get the file URL
    CFURLRef fileURL =
    CFURLCreateWithFileSystemPath(kCFAllocatorDefault,
                                  (CFStringRef)filePath,
                                  kCFURLPOSIXPathStyle,
                                  (Boolean)false);
    if (!fileURL) goto done;
    // Create and open the read stream
    readStream = CFReadStreamCreateWithFile(kCFAllocatorDefault,
                                            (CFURLRef)fileURL);
    if (!readStream) goto done;
    bool didSucceed = (bool)CFReadStreamOpen(readStream);
    if (!didSucceed) goto done;
    // Initialize the hash object
    CC_MD5_CTX hashObject;
    CC_MD5_Init(&hashObject);
    // Make sure chunkSizeForReadingData is valid
    if (!chunkSizeForReadingData) {
        chunkSizeForReadingData = 1024 * 8;
    }
    // Feed the data to the hash object
    bool hasMoreData = true;
    while (hasMoreData) {
        uint8_t buffer[chunkSizeForReadingData];
        CFIndex readBytesCount = CFReadStreamRead(readStream,(UInt8 *)buffer,(CFIndex)sizeof(buffer));
        if (readBytesCount == -1) break;
        if (readBytesCount == 0) {
            hasMoreData = false;
            continue;
        }
        CC_MD5_Update(&hashObject,(const void *)buffer,(CC_LONG)readBytesCount);
    }
    // Check if the read operation succeeded
    didSucceed = !hasMoreData;
    // Compute the hash digest
    unsigned char digest[CC_MD5_DIGEST_LENGTH];
    CC_MD5_Final(digest, &hashObject);
    // Abort if the read operation failed
    if (!didSucceed) goto done;
    // Compute the string result
    char hash[2 * sizeof(digest) + 1];
    for (size_t i = 0; i < sizeof(digest); ++i) {
        snprintf(hash + (2 * i), 3, "%02x", (int)(digest[i]));
    }
    result = CFStringCreateWithCString(kCFAllocatorDefault,(const char *)hash,kCFStringEncodingUTF8);
    
done:
    if (readStream) {
        CFReadStreamClose(readStream);
        CFRelease(readStream);
    }
    if (fileURL) {
        CFRelease(fileURL);
    }
    return result;
}


@end
