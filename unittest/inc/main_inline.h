//
// main_inline.h
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//


template< typename AlgImp >
VOID addImplementationToGlobalList()
{
    std::string algName = AlgImp::s_algName;
    std::string impName = AlgImp::s_impName;
    std::string modeName = AlgImp::s_modeName;
    std::string algModeName = algName + modeName;

    if( setContainsPrefix( g_algorithmsToTest, algModeName ) &&
        setContainsPrefix( g_implementationsToTest, impName ) )
    {
        AlgorithmImplementation * p;
        try
        {
            p = new AlgImp();
        }
        catch( NTSTATUS status )
        {
            UNREFERENCED_PARAMETER( status );
            iprint( "\nUnsupported algorithm %s/%s, skipping...", impName.c_str(), algName.c_str() );
            return;
        }
        p->m_algorithmName = algName;
        p->m_implementationName = impName;
        p->m_modeName = modeName;
        g_algorithmImplementation.push_back( p );
    }
}

template< typename AlgImp >
VOID addImplementationToList(AlgorithmImplementationVector * pAlgorithmImplementationVector)
{
    std::string algName = AlgImp::s_algName;
    std::string impName = AlgImp::s_impName;
    std::string modeName = AlgImp::s_modeName;

    AlgorithmImplementation * p;
    try
    {
        p = new AlgImp();
    }
    catch( NTSTATUS status )
    {
        UNREFERENCED_PARAMETER( status );
        iprint( "\nUnsupported algorithm %s/%s, skipping...", impName.c_str(), algName.c_str() );
        return;
    }

    p->m_algorithmName = algName;
    p->m_implementationName = impName;
    p->m_modeName = modeName;
    (*pAlgorithmImplementationVector).push_back( p );
}


template< typename AlgType >
std::unique_ptr<std::vector< AlgType * >>  getAlgorithmsOfOneType()
{
    std::unique_ptr<std::vector< AlgType * >> result( new std::vector< AlgType * > );

    for( std::vector<AlgorithmImplementation *>::iterator i = g_algorithmImplementation.begin();
            i != g_algorithmImplementation.end();
            i++ )
    {
        AlgType * pAlg;
        pAlg = dynamic_cast< AlgType * > (*i);
        if( pAlg != NULL )
        {
            result->push_back( pAlg );
        }
    }

    return result;
}

template<typename AlgorithmType>
VOID getAllImplementations( String algName, std::vector<AlgorithmType *> *res )
{
    for( AlgorithmImplementationVector::const_iterator i= g_algorithmImplementation.begin(); i != g_algorithmImplementation.end(); ++i )
    {
        if( (*i)->m_algorithmName + (*i)->m_modeName == algName )
        {
            AlgorithmType * p = dynamic_cast< AlgorithmType *>( *i );
            CHECK( p != NULL, "Wrong algorithm name/type combo" );
            res->push_back( p );
        }
    }
}

BOOL
isAlgorithmPresent( String algName, BOOL isPrefix );

