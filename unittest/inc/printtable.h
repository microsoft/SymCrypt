//
// PrintTable.h
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

class PrintTable
{
public:
    PrintTable();
    ~PrintTable();

private:
    PrintTable( const PrintTable & );
    void operator=( const PrintTable & );

public:
    VOID addItem( String row, String col, String item );
    VOID addItem( String row, String col, ULONGLONG value );
    VOID addItemNonZero( String row, String col, ULONGLONG value );
    VOID addItem( String row, String col, double perByte, double overhead, double range );

    VOID clear();

    VOID print( String heading );

private:
    typedef std::pair<String,String>    RowCol;
    typedef std::vector<String>         StringVector;
    typedef std::map<RowCol, String>    ItemMap;

    StringVector m_rows;
    StringVector m_cols;

    ItemMap m_items;
};
