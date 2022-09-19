//
// KAT file infrastructure
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//
// Our KAT files have the following generic format:
//
// ASCII text
// Category markers of the form [text] at the start of a line.
// Data sets consist of one or more records terminated by an empty line,
// category marker, or end-of-file.
// Each record is of the form fieldname = data.
// White space is ignored and stripped where possible.
// Comments are anything starting with # and running to the end of the line
// Comments can appear anywhere where whitespace can.
//

typedef enum{ 
    KAT_TYPE_CATEGORY,          // a [<text>] category marker. Text is in categoryName field
    KAT_TYPE_DATASET,
    KAT_TYPE_END 
} KAT_ITEM_TYPE;

typedef struct _KAT_DATA_ITEM
{
    String      name;
    String      data;
    LONGLONG    line;           // line number
} KAT_DATA_ITEM;

typedef std::vector<KAT_DATA_ITEM> DataItems;

typedef struct _KAT_RECORD
{
    KAT_ITEM_TYPE   type;
    String          categoryName;
    DataItems       dataItems;
    LONGLONG        line;       // line number of first line in record
} KAT_ITEM, *PKAT_ITEM;


class KatData
{
public:
    KatData( _In_ PSTR name, _In_ PCCHAR pbData, SIZE_T cbData );
    // Provide name, pointer, and length of data to be parsed
    ~KatData() {};

private:
    KatData( const KatData & );
    VOID operator=( const KatData & );


    int next();

    BOOL isEmpty();

    VOID advance();

    VOID skipSpace();

    VOID skipNewlines();

    BOOL atEol();


public:
    PCCHAR      m_pbData;           // Current data location
    PCCHAR      m_pbEnd;            // End of data
    LONGLONG    m_line;             // Current line number
    LPSTR       m_name;             // Name of file/resource

    LONGLONG    line();

    VOID getKatItem( PKAT_ITEM pKat );
};

BString katParseData( KAT_ITEM & item, LPCSTR name );
    //
    // Turn a string notation into a binary string.
    // There are several encodings used:
    // - Hex string
    // - text string delimited with double quotes
    // - 'repeat' '(' <integer> ')' <encoded string>
    // line number is passed for error reporting purposes.
    //

LONGLONG katParseInteger( KAT_ITEM & item, LPCSTR name );
 
BOOL katIsFieldPresent( KAT_ITEM & item, LPCSTR name );

const KAT_DATA_ITEM * findDataItem( KAT_ITEM & item, LPCSTR name );
    
    
