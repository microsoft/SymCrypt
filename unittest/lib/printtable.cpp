//
// PrintTable.cpp   Print pretty tables
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"

PrintTable::PrintTable()
{
}

PrintTable::~PrintTable()
{
}

VOID
PrintTable::clear()
{
    m_rows.clear();
    m_cols.clear();
    m_items.clear();
}

VOID
PrintTable::addItem( String row, String col, String item )
{
    //print( "%s\n", item.c_str() );

    if( find( m_rows.begin(), m_rows.end(), row ) == m_rows.end() )
    {
        m_rows.push_back( row );
    }
    if( find( m_cols.begin(), m_cols.end(), col ) == m_cols.end() )
    {
        m_cols.push_back( col );
    }

    std::pair<String,String> key( row, col );

    m_items[ key ] = item;
}

VOID
PrintTable::addItem( String row, String col, ULONGLONG item )
{
    std::ostringstream s;

    s << item;

    addItem( row, col, s.str() );
}

VOID
PrintTable::addItemNonZero( String row, String col, ULONGLONG item )
{
    if( item != 0 )
    {
        addItem( row, col, item );
    }
}


VOID
PrintTable::addItem( String row, String col, double perByte, double overhead, double range )
{
    double intOverhead = floor( overhead + 0.5 );
    double intRange = floor( range + 0.5 );
    String data;
    String sep;

    if( perByte != 0.0 )
    {
        //
        // We want to have a fixed width
        // and fixed precision for the clocks per byte value
        // There is no easy way to do this with format specifiers
        //
        /*
        if( perByte < 0.0 )
        {
            perByte = -perByte;
            SNPRINTF_S( buf1, sizeof( buf1 ), _TRUNCATE, "-%1d.%02dn",
                (int)floor(perByte), (int) ( 100.0 * fmod( perByte, 1 ) ) );
        }
        else if( perByte < 99.99 )
        {
            SNPRINTF_S( buf1, sizeof( buf1 ), _TRUNCATE, "%2d.%02dn",
                (int)floor(perByte), (int) ( 100.0 * fmod( perByte, 1 ) ) );
        }
        else if( perByte < 999.9 )
        {
            SNPRINTF_S( buf1, sizeof( buf1 ), _TRUNCATE, "%3d.%1dn",
                (int)floor(perByte), (int) ( 10.0 * fmod( perByte, 1 ) ) );
        } else
        {
            SNPRINTF_S( buf1, sizeof( buf1 ), _TRUNCATE, "%.0fn", perByte );
        }
        */
        data = formatNumber( perByte ) + "n";
        sep = "+";
    }
    if( overhead != 0.0 )
    {
        data  = data + sep + formatNumber( intOverhead );
        // SNPRINTF_S( buf1, sizeof( buf1 ), _TRUNCATE, "%4d", intOverhead );
        // data = data + sep + buf1;
        sep = "+-";
    } else
    {
        data = data + "     ";
        sep = "+-";
    }

    if( g_showPerfRangeInfo )
    {
        if( range != 0.0 )
        {
            //SNPRINTF_S( buf1, sizeof( buf1 ), _TRUNCATE, "%4d", intRange );
            //data = data + sep + buf1;
            data = data + sep + formatNumber( intRange );
        } else
        {
            data = data + "      ";
        }
    }

    addItem( row, col, data );

}

VOID
PrintTable::print( String heading )
{
    static int nSpacesBetweenColumns = 1;
    sort( m_rows.begin(), m_rows.end() );
    sort( m_cols.begin(), m_cols.end() );

    SIZE_T nCols = m_cols.size();
    SIZE_T nRows = m_rows.size();

    if( nCols == 0 )
    {
        // Do not print empty tables
        return;
    }

    std::vector<SIZE_T> colSize( nCols + 1, 0 );

    //
    // Compute the width of the first column (row headers)
    //
    for( SIZE_T r=0; r<nRows; r++ )
    {
        colSize[0] = SYMCRYPT_MAX( colSize[0], m_rows[r].size() + 1 );
    }

    //
    // Compute the width of the other columns
    //
    for( SIZE_T c=0; c<nCols; c++ )
    {
        //print( "%d\n", m_cols[c].size() );
        colSize[c+1] = SYMCRYPT_MAX( colSize[ c+1 ], m_cols[c].size() );
    }

    for( SIZE_T r=0; r<nRows; r++ )
    {
        for( SIZE_T c=0; c<nCols; c++ )
        {
            // print( "%d(%s) %d(%s)\n", i, m_rows[i].c_str(), j, m_cols[j].c_str() );
            SIZE_T s = m_items[ make_pair( m_rows[r], m_cols[c] ) ].size();
            // print( "%d %s\n", s, m_items[ make_pair( m_rows[r], m_cols[c] ) ].c_str() );
            colSize[ c+1 ] = SYMCRYPT_MAX( colSize[ c+1 ], s );
        }
    }

    ::print( "\n" );
    ::print( heading );
    ::print( ":\n" );

    //
    // Print column headers
    //
    ::print( "%*s", colSize[0], "" );
    SIZE_T totalWidth = colSize[0];
    for( SIZE_T c=0; c<nCols; c++ )
    {
        ::print( "%*s%*s", nSpacesBetweenColumns, "", colSize[ c+1 ], m_cols[c].c_str() );
        totalWidth += colSize[ c+1 ] + nSpacesBetweenColumns;
    }
    ::print( "\n" );
    for( SIZE_T i=0; i<totalWidth; i++ )
    {
        ::print( "=" );
    }
    ::print( "\n" );

    for( SIZE_T r=0; r<nRows; r++ )
    {
        ::print( "%*s:", colSize[0]-1, m_rows[r].c_str() );

        char * sep = " ";
        for( SIZE_T c=0; c<nCols; c++ )
        {
            ::print( "%-*s%*s", nSpacesBetweenColumns, sep, colSize[ c+1 ], m_items[ make_pair( m_rows[r], m_cols[c] ) ].c_str() );
            sep = " ";
        }

        ::print( "\n" );
    }


}


