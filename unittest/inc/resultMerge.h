//
// Result merge infrastructure
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

class ResultMerge {
public:
    ResultMerge();
    ~ResultMerge();

private:
    ResultMerge( const ResultMerge & );
    VOID operator=( const ResultMerge & );

public:
    VOID addResult( 
        _In_                        AlgorithmImplementation * pAlgImp, 
        _In_reads_( cbData )       PCBYTE pbData, 
                                    SIZE_T cbData );

    VOID getResult( 
        _Out_writes_( cbResult )    PBYTE   pbResult, 
                                    SIZE_T  cbResult, 
                                    BOOL    countInvocation = TRUE );

private:
    typedef struct
    {
        AlgorithmImplementation *   pAlgImp;
        BString                      strData;
        SIZE_T                      nAgree;
    } ResultItem;

    std::vector<ResultItem> m_results;

};
