//
//  main.mm
//  symcryptunittest_iOS
//
//  Created by Yannis Rouselakis on 7/1/15.
//  Copyright (c) 2015 Microsoft. All rights reserved.
//

#import <UIKit/UIKit.h>
#import "AppDelegate.h"

#include <stdio.h>
#include "precomp.h"
#include "sc_implementations.h"

SYMCRYPT_ENVIRONMENT_GENERIC

char * g_implementationNames[] =
{
    ImpSc::name,
    NULL,
};

int main(int argc, char * argv[]) {
   
    initTestInfrastructure(0, NULL);
    
    addSymCryptAlgs();
    
    runFunctionalTests();
    
    exitTestInfrastructure();
    
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
