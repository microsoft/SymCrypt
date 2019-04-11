//
// hash_imp_pattern.h
//
// Pattern file for the hash implementations.
// This file is #included with two macros defined:
//  HASH_NAME   name of hash function in all caps
//  HASH_Name   name of hash function with one capital letter and the rest lowercase
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//


class HASH_CLASS_NAME( HASH_Name ): public HashImplementation
{
public:
    HASH_CLASS_NAME(HASH_Name)() {};
    virtual ~HASH_CLASS_NAME(HASH_Name)() {};

private:
    HASH_CLASS_NAME(HASH_Name)( const & HASH_CLASS_NAME(HASH_Name) );
    VOID operator=( const & HASH_CLASS_NAME(HASH_Name) );

public:
    static const std::string s_algName;
    static const std::string s_impName;

    virtual SIZE_T resultLen();
    virtual SIZE_T inputBlockLen();

    virtual HashComputation * newHashComputation();
    virtual VOID hash( PCBYTE pbData, SIZE_T cbData, PBYTE pbResult, SIZE_T cbResult );
};

class HASH_COMP_CLASS_NAME( HASH_Name ): public HashComputation
{
public:
    HASH_COMP_CLASS_NAME( HASH_Name )() {};
    virtual ~HASH_COMP_CLASS_NAME( HASH_Name ) () {};

private:
    HASH_COMP_CLASS_NAME( HASH_Name )( const & HASH_COMP_CLASS_NAME( HASH_Name ) );
    VOID operator=( const & HASH_COMP_CLASS_NAME( HASH_Name ) );

public:
    virtual void init();
    virtual void append( PCBYTE pbData, SIZE_T cbData );
    virtual void result( PBYTE pbResult, SIZE_T cbResult );

    HASH_STATE( HASH_NAME )  state;
};

