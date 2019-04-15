//
//  Helper functions for the iOS environment
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#import <UIKit/UIKit.h>
#import <Security/Security.h>

#include "precomp.h"

KatData * 
getCustomResource( PSTR resourceName, PSTR resourceType )
{
    UNREFERENCED_PARAMETER(resourceType);
    
    NSString *fullName = [NSString stringWithUTF8String: resourceName];
    CHECK( fullName != NULL, "Failed to get the resource full name");
    
    NSString *filePath = [[NSBundle mainBundle] pathForResource:[fullName stringByDeletingPathExtension] ofType:[fullName pathExtension]];
    CHECK( filePath != NULL, "Failed to find resource");
    
    NSData *content = [NSData dataWithContentsOfFile:filePath];
    CHECK( content != NULL, "Failed to retrieve the content of the resource");

    return new KatData( resourceName, (PCCHAR) [content bytes], [content length] );
}

NTSTATUS
IosGenRandom( PBYTE pbBuf, UINT32 cbBuf )
{
    //arc4random_buf( (PBYTE)pbBuf, cbBuf ); 
    
    return (NTSTATUS) SecRandomCopyBytes( kSecRandomDefault, cbBuf, pbBuf );
    
}