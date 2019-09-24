//
// Kat implementation file
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"

CHAR charToLower( CHAR c )
{
    return (CHAR) tolower( c );
}


String strip( const String & strIn )
{
    String s = strIn;
    while( s.size() > 0 && (s[0] == ' ' || s[0] == '\t' ))
    {
        s.erase( 0, 1 );
    }

    while( s.size() > 0 && (s[ s.size()-1 ] == ' ' || s[ s.size() - 1 ] == '\t' ) )
    {
        s.erase( s.size() - 1 );
    }
    return s;
}



KatData::KatData( _In_ PSTR name, _In_ PCCHAR pbData, SIZE_T cbData )
{
    m_line = 1;
    m_pbData = pbData;
    m_pbEnd = pbData + cbData;
    m_name = name;
}

LONGLONG
KatData::line()
{
    return m_line;
}

int
KatData::next()
{
    return * m_pbData;
}

BOOL
KatData::isEmpty()
{
    return m_pbData >= m_pbEnd;
}

VOID
KatData::advance()
{
    if( !isEmpty() )
    {
        if( next() == '\n' )
        {
            m_line++;
        }
        ++m_pbData;
    }
}

VOID
KatData::skipSpace()
{
    //
    // Skip white space
    //
    while( !isEmpty() && (next() == ' ' || next() == '\t' ) )
    {
        advance();
    }

    //
    // Skip any comments
    //
    if( !isEmpty() && next() == '#' )
    {
        while( !atEol() )
        {
            advance();
        }
    }
}

VOID
KatData::skipNewlines()
{
    while( !isEmpty() && atEol() )
    {
        advance();
    }
}

BOOL
KatData::atEol()
{
    return isEmpty() || next() == '\r' || next() == '\n';
}


VOID
KatData::getKatItem( PKAT_ITEM pKatItem )
{
    BOOL inDataSet = FALSE;
    for(;;)
    {
        skipSpace();
        if( atEol() )
        {
            //
            // We found an empty line, or are at the end of the data
            //
            if( inDataSet )
            {
                //
                // Found end of data set, return
                //
                skipNewlines();
                pKatItem->type = KAT_TYPE_DATASET;
                break;
            }
            else
            {
                //
                // Empty line, not in data set
                //
                if( isEmpty() )
                {
                    //
                    // End of file
                    //
                    pKatItem->type = KAT_TYPE_END;
                    break;
                }
                //
                // Skip empty lines
                //
                skipNewlines();
                continue;
            }

        }

        if( next() == '[' )
        {
            //
            // We found a category marker.
            //
            if( inDataSet )
            {
                FATAL2( "Missing blank line before category [...] marker on line %lld", line() );
            }

            PCCHAR pbStart = m_pbData;
            LONGLONG startLine = m_line;
            while( !atEol() && next() != ']' )
            {
                advance();
            }

            if( atEol() )
            {
                FATAL2( "Unclosed '[' in line %lld", startLine );
            }

            PCCHAR pbEnd = m_pbData;
            advance();      // skip ']'

            skipSpace();
            if( !atEol() )
            {
                FATAL2( "Extra data after '[...]' in line %lld", m_line );
            }

            pKatItem->type = KAT_TYPE_CATEGORY;
            pKatItem->categoryName.assign( (const char *)pbStart + 1, pbEnd - pbStart - 1 );

            skipNewlines();
            break;
        }

        {
            //
            // We must have a <id> = <data> pair
            //
            PCCHAR nameStart = m_pbData;
            LONGLONG startLine = m_line;
            while( !atEol() && next() != '=' )
            {
                advance();
            }

            if( atEol() )
            {
                FATAL2( "Missing = in line %lld", startLine );
            }

            PCCHAR nameEnd = m_pbData;

            advance();          // skip '='
            PCCHAR dataStart = m_pbData;
            while( !atEol() )
            {
                advance();
            }
            PCCHAR dataEnd = m_pbData;

            String name( nameStart, nameEnd - nameStart );
            String data( dataStart, dataEnd - dataStart );

            name = strip( name );
            data = strip( data );

            if( !inDataSet )
            {
                inDataSet = TRUE;
                pKatItem->dataItems.clear();
                pKatItem->line = m_line;
            }

            KAT_DATA_ITEM katItem;

            //
            // Convert the name to lowercase
            //
            for( SIZE_T i=0; i<name.size(); i++ )
            {
                name[i] = charToLower( name[i] );
            }
            katItem.name = name;
            katItem.data= data;
            katItem.line = m_line;

            if( katIsFieldPresent( *pKatItem, name.c_str() ) )
            {
                FATAL3( "Duplicate data field \"%s\"in data set in line %lld", name.c_str(), line() );
            }
            pKatItem->dataItems.push_back( katItem ) ;

            //
            // Skip a single newline
            //
            if( !isEmpty() && next() == '\r' )
            {
                advance();
            }
            if( !isEmpty() && next() == '\n' )
            {
                advance();
            }
        }

    }
}

BYTE hexToNibble( char ch, LONGLONG line )
{
    int c = toupper( ch );
    if( c >= '0' && c <= '9' )
    {
        return (BYTE)(c - '0');
    }
    if( c >= 'A' && c <= 'F' )
    {
        return (BYTE)(c - 'A' + 10);
    }
    FATAL2( "Invalid hex character in line %lld", line );
    return 0;
}

BYTE hexToByte( _In_reads_( 2 ) char * in, LONGLONG line )
{
    return (hexToNibble( in[0], line ) << 4 ) + hexToNibble( in[1], line );
}



BString katParseData( String data, LONGLONG line )
{

    SIZE_T len = data.size();
    BString result;

    if( len > 1 && data[0] == '"' && data[len-1] == '"' )
    {
        result.assign( (BYTE *)&data[1], len-2 );
        return result;
    }

    if( data.find( "repeat" ) == 0 )
    {
        SIZE_T iOpen = data.find( '(' );

        SIZE_T iClose = data.find( ')' );
        if( iOpen + 1 >= iClose || iOpen == data.npos || iClose == data.npos )
        {

            FATAL3( "Wrong parenthesis in repeat format, line %lld = %s", line, data.c_str() )
        }

        String repeatStr = strip( data.substr( iOpen + 1, iClose ) );

        int repValue = atoi( repeatStr.c_str() );

        BString repData = katParseData( strip( data.substr( iClose+1 ) ), line );
        SIZE_T repLen = repData.size();

        PBYTE pResult = new BYTE[ repLen * repValue ];
        CHECK( pResult != NULL, "Out of memory" );

        for( int i=0; i<repValue; i++ )
        {
            memcpy( pResult + i*repLen, repData.data(), repLen );
        }

        BString result( pResult, repLen * repValue );

        delete [] pResult;

        return result;

    }

    if( (len & 1) != 0 )
    {
        FATAL2( "Hex data has odd number of characters in line %lld", line );
    }

    result.assign( len/2, 0 );

    for( SIZE_T i=0; i<len/2; i++ )
    {
        result[i] = hexToByte( &data[2*i], line );
    }

    return result;

}

const KAT_DATA_ITEM * findDataItem( KAT_ITEM & item, LPCSTR name )
{
    for( DataItems::const_iterator i = item.dataItems.begin(); i != item.dataItems.end(); ++ i )
    {
        if( i->name == name )
        {
            return &*i;
        }
    }
    return NULL;
}

BString katParseData( KAT_ITEM & item, LPCSTR name )
{
    const KAT_DATA_ITEM * dataItem = findDataItem( item, name );
    CHECK4( dataItem != NULL, "Could not find data field \"%s\" in record at line %lld", name, item.line );
    return katParseData( dataItem->data, dataItem->line );
}


LONGLONG katParseInteger( KAT_ITEM &item, LPCSTR name )
{
    LPCSTR data;
    LONGLONG res;

    const KAT_DATA_ITEM * dataItem = findDataItem( item, name );
    CHECK4( dataItem != NULL, "Could not find data field \"%s\" in record at line %lld", name, item.line );
    data = dataItem->data.c_str();
    if( data[0] == '0' && data[1] == 'x' )
    {
        sscanf( data, "0x%" PRIx64, &res );
    } else {
        res = atol( data );
    }

    //iprint( "Converted %s into 0x%llx\n", data, res );

    return res;
}

BOOL katIsFieldPresent( KAT_ITEM & item, LPCSTR name )
{
    const KAT_DATA_ITEM * dataItem = findDataItem( item, name );
    return dataItem != NULL;
}

