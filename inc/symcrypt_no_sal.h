//
// symcrypt_no_sal.h
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

//
// This header file suppresses all SAL annotation for use in
// environments without SAL, such as iOS or Android.
//

#define _Success_(x)
#define _Analysis_noreturn_
#define _Analysis_assume_(x)
#define __analysis_assume(x)

#define _Use_decl_annotations_

#define __in
#define __in_opt
#define __inout_ecount(x)
#define __out_ecount(x)

#define _In_
#define _In_z_
#define _In_z_b
#define _In_opt_
#define _In_range_(x,y)
#define _In_reads_(x)
#define _In_reads_opt_(x)
#define _In_reads_bytes_(x)
#define _In_reads_bytes_opt_(x)

#define _Out_
#define _Out_opt_
#define _Out_writes_(x)
#define _Out_writes_to_(x,y)
#define _Out_writes_opt_(x)
#define _Out_writes_bytes_(x)
#define _Out_writes_bytes_to_(x,y)
#define _Out_writes_bytes_all_opt_(x)
#define _Out_writes_bytes_opt_(x)

#define _Inout_
#define _Inout_updates_(x)
#define _Inout_updates_bytes_(x)
#define _Inout_updates_opt_(x)

#define _Field_size_(x)
#define _Field_range_(x,y)

#define _Ret_range_(x,y)

#define _Must_inspect_result_
