//
// symcrypt_no_sal.h
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

//
// This header file suppresses all SAL annotation for use in
// environments without SAL, such as iOS or Android.
//

#ifndef _Success_
#define _Success_(x)
#endif
#ifndef _Analysis_noreturn_
#ifdef __GNUC__
#define _Analysis_noreturn_ [[gnu::noreturn]]
#else
#define _Analysis_noreturn_
#endif
#endif
#ifndef _Analysis_assume_
#define _Analysis_assume_(x)
#endif
#ifndef __analysis_assume
#define __analysis_assume(x)
#endif

#ifndef _Use_decl_annotations_
#define _Use_decl_annotations_
#endif

#ifndef __in
#define __in
#endif
#ifndef __in_opt
#define __in_opt
#endif
#ifndef __inout_ecount
#define __inout_ecount(x)
#endif
#ifndef __out_ecount
#define __out_ecount(x)
#endif

#ifndef _In_
#define _In_
#endif
#ifndef _In_z_
#define _In_z_
#endif
#ifndef _In_z_b
#define _In_z_b
#endif
#ifndef _In_opt_
#define _In_opt_
#endif
#ifndef _In_range_
#define _In_range_(x,y)
#endif
#ifndef _In_reads_
#define _In_reads_(x)
#endif
#ifndef _In_reads_opt_
#define _In_reads_opt_(x)
#endif
#ifndef _In_reads_bytes_
#define _In_reads_bytes_(x)
#endif
#ifndef _In_reads_bytes_opt_
#define _In_reads_bytes_opt_(x)
#endif

#ifndef _Out_
#define _Out_
#endif
#ifndef _Out_opt_
#define _Out_opt_
#endif
#ifndef _Out_writes_
#define _Out_writes_(x)
#endif
#ifndef _Out_writes_to_
#define _Out_writes_to_(x,y)
#endif
#ifndef _Out_writes_opt_
#define _Out_writes_opt_(x)
#endif
#ifndef _Out_writes_bytes_
#define _Out_writes_bytes_(x)
#endif
#ifndef _Out_writes_bytes_to_
#define _Out_writes_bytes_to_(x,y)
#endif
#ifndef _Out_writes_bytes_all_opt_
#define _Out_writes_bytes_all_opt_(x)
#endif
#ifndef _Out_writes_bytes_opt_
#define _Out_writes_bytes_opt_(x)
#endif

#ifndef _Inout_
#define _Inout_
#endif
#ifndef _Inout_updates_
#define _Inout_updates_(x)
#endif
#ifndef _Inout_updates_bytes_
#define _Inout_updates_bytes_(x)
#endif
#ifndef _Inout_updates_opt_
#define _Inout_updates_opt_(x)
#endif

#ifndef _Field_size_
#define _Field_size_(x)
#endif
#ifndef _Field_range_
#define _Field_range_(x,y)
#endif

#ifndef _Ret_range_
#define _Ret_range_(x,y)
#endif

#ifndef _Must_inspect_result_
#define _Must_inspect_result_
#endif

#ifndef __callback
#define __callback
#endif