//
// ResultMerge implementation file
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

#include "precomp.h"

ResultMerge::ResultMerge()
{
}

ResultMerge::~ResultMerge()
{
}

_Use_decl_annotations_
VOID
ResultMerge::addResult( AlgorithmImplementation * pAlgImp, PCBYTE pbData, SIZE_T cbData )
{
    ResultItem item;

    item.pAlgImp = pAlgImp;
    item.strData.assign( pbData, cbData );
    item.nAgree = 0;

    m_results.push_back( item );
}

_Use_decl_annotations_
VOID
ResultMerge::getResult( PBYTE pbResult, SIZE_T cbResult, BOOL countInvocation )
{
    memset( pbResult, 0, cbResult );

    SIZE_T nResults = m_results.size();
    SIZE_T maxAgree = 0;

    CHECK( nResults != 0, "No results present" );

/*
    print( "ResultMerge state:\n" );
    for( std::vector<ResultItem>::iterator i = m_results.begin(); i != m_results.end(); ++i )
    {
        print( "    " );
        printHex( i->strData.data(), i->strData.size() );
        print( " from %5s/%s\n", i->pAlgImp->m_implementationName.c_str(), i->pAlgImp->m_algorithmName.c_str() );
    }
*/

    for( std::vector<ResultItem>::iterator i= m_results.begin(); i!= m_results.end(); ++i )
    {
        for( std::vector<ResultItem>::const_iterator j= m_results.begin(); j!= m_results.end(); ++j )
        {
            if( i->strData == j->strData )
            {
                i->nAgree++;
                maxAgree = SYMCRYPT_MAX( maxAgree, i->nAgree );
            }
        }
    }

    BString result;
    BOOL resultFound = FALSE;
    for( std::vector<ResultItem>::iterator i = m_results.begin(); i!= m_results.end(); ++i )
    {
        if( countInvocation )
        {
            i->pAlgImp->m_nResults++;
        }
        if( i->nAgree * 2 > nResults )
        {
            result = i->strData;
            resultFound = TRUE;
        } 
        else if( maxAgree * 2 > nResults )
        {
            i->pAlgImp->m_nErrorDisagreeWithMajority++;
        } 
        else
        {
            i->pAlgImp->m_nErrorNoMajority++;
        }
    }

    if( !resultFound )
    {
        print( "No majority result amongst\n" );
        for( std::vector<ResultItem>::iterator i = m_results.begin(); i != m_results.end(); ++i )
        {
            printHex( i->strData.data(), i->strData.size() );
            print( " from %5s/%s\n", i->pAlgImp->m_implementationName.c_str(), i->pAlgImp->m_algorithmName.c_str() );
        }
        print( "Picking first one\n" );
        result = m_results[0].strData;
    }

    CHECK( result.size() == cbResult, "Final result has wrong length" );

    memcpy( pbResult, result.data(), cbResult );
}
