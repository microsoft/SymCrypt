//
// ScBuild.cs
// SymCrypt build tool
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

using System;
using System.IO;
using System.Collections;
using System.Diagnostics;
using System.Text.RegularExpressions;

namespace ScBuild{

static public class Output
{
    public static int OutputIndent = 0;

    public static ArrayList AllOutput = new ArrayList();

    public static void Print( params object[] args)
    {
        string s;
        if( args.Length == 1 )
        {
            s = (string) args[0];
        } else
        {
            object [] t = new object[ args.Length - 1 ];
            Array.Copy( args, 1, t, 0, args.Length - 1 );
            s = String.Format( (string)args[0], t );
        }

        if( outputFile != null )
        {
            outputFile.Write( s.Replace( "\n", outputFile.NewLine ) );
        }
        System.Console.Write( s );
        AllOutput.Add( s );

    }

    public static void OpenLogFile( string filename )
    {
        outputFile = File.CreateText( filename );
    }

    public static void CloseLogFile()
    {
        if( outputFile != null )
        {
            outputFile.Close();
            outputFile = null;
        }
    }

    static StreamWriter outputFile = null;

}


public class FatalException: Exception
{
    public FatalException( string m ) : base( m ) {}
}


class ScBuild
{
    string LogDateTimeFormat = "yyyy-MM-dd HH:mm:ss.ff";

    Random m_random;

    public IDictionary m_environment;
    public string m_SymCryptDir;

    string m_currentBranch;

    public static void Print( params object[] args )
    {
        Output.Print( args );
    }

    public static void Fatal( params object[] args )
    {
        object [] t = new object[ args.Length - 1 ];
        Array.Copy( args, 1, t, 0, args.Length - 1 );
        string s = String.Format( (string)args[0], t );

        Print( "*\n\n" );

        throw new FatalException( "\n" + s );
    }


    //
    // Helper functions for running other programs
    //
    public string[] Run( string ExeName, string Arguments )
    {
        Print( "> " + ExeName + " " + Arguments + "\n" );
        RunStdout.Clear();
        RunStderr.Clear();

        System.Diagnostics.Process p = new System.Diagnostics.Process();

        p.StartInfo.FileName = ExeName;
        p.StartInfo.Arguments = Arguments;
        p.StartInfo.CreateNoWindow = true;
        p.StartInfo.UseShellExecute = false;    // Needed for stdout/stderr redirection
        p.StartInfo.RedirectStandardError = true;
        p.StartInfo.RedirectStandardOutput = true;
        p.StartInfo.RedirectStandardInput = true;

        p.OutputDataReceived += new DataReceivedEventHandler( StdOutDataHandler );
        p.ErrorDataReceived += new DataReceivedEventHandler( StdErrDataHandler );


        p.Start();
        p.BeginOutputReadLine();
        p.BeginErrorReadLine();
        p.WaitForExit();

        //
        // Should improve this: strip trailing empty lines from both of the outputs
        //

        string [] s = new string[RunStdout.Count + RunStderr.Count ];

        for( int i=0; i<RunStdout.Count; i++ )
        {
            s[i] = (string) RunStdout[i];
        }

        for( int i=0; i<RunStderr.Count; i++ )
        {
            s[i + RunStdout.Count] = (string) RunStderr[i];
        }

        return s;

    }

    public static void StdOutDataHandler( object sendingProcess, DataReceivedEventArgs OutLine )
    {
        if( !String.IsNullOrEmpty( OutLine.Data ) )
        {
            string s = "  " + OutLine.Data;

            //Print( "Stdout output: " + s );

            RunStdout.Add( s);
            Print( s + "\n" );
        }
    }

    public static void StdErrDataHandler( object sendingProcess, DataReceivedEventArgs OutLine )
    {
        if( !String.IsNullOrEmpty( OutLine.Data ) )
        {
            string s = "* " + OutLine.Data;

            //Print( "Stderr output: " + s );

            RunStderr.Add( s );
            Print( s + "\n" );
        }
    }

    public string[] RunCmd( string relDir, string CommandLine )
    {
        Print( relDir + "> " + CommandLine + "\n" );
        string exeName =  m_environment[ "windir" ] + @"\system32\cmd.exe" ;
        string args = CommandLine;
        if( relDir.Length != 0 )
        {
            args = "cd " + relDir + " && " + args;
        }
        args = String.Format( "/c \"{0}\"", args );
        return Run( exeName, args );
    }



    public void MoveFile( string src, string dst )
    {
        string [] res = RunCmd( "", "move " + src + " " + dst );
        if( res.Length != 1 || !Regex.IsMatch( res[0], @"\s+1\s+file\(s\) moved." ) )
        {
            foreach( string pat in new string [] {
                    @".*",
                    @"\s+1.*",
                    @"\s+1\s+",
                    @"\s+1\s+file",
                    @"\s+1\s+file(s)",
                    @"\s+1\s+file(s) moved",
                    @"\s+1\s+file(s) moved.",
                } )
            {
                Print( "[{0}] {1} \n", pat, Regex.IsMatch( res[0], pat ) );
            }
            Fatal( "Unexpected response from file move {0} [{1}]", res.Length, res[0] );
        }
    }

    public void CopyFile( string src, string dst )
    {
        string [] res = RunCmd( "", "copy " + src + " " + dst );
        if( res.Length != 1 || !Regex.IsMatch( res[0], @"\s+1\s+file\(s\) copied." ) )
        {
            Fatal( "Unexpected response from file copy (lines ={0} [{1}])", res.Length, res[0] );
        }
    }


    static string[] m_banned_symbols = new string[] {
        // Split each symbol so that we don't match against this source file...
        "_" + "KERNEL_MODE",        // all our code is compiled with the /kernel flag which sets this symbol, but that doesn't mean we run in kernel mode
        };

    public void CheckForBannedSymbols()
    {
        foreach( string sym in m_banned_symbols ){
            string [] res = RunCmd( "", "findstr -spr \"\\<" + sym + "\\>\" *.c *.h *.cs *.cpp" );
            if( res.Length != 0 )
            {
                Fatal( "Found banned symbol \"{0}\"", sym );
            }
        }
    }

    int m_nBuildError = 0;
    public void Build( string subDir, string arch )
    {
        string[] res = RunCmd(subDir, "razzle " +arch + " no_oacr exec build -c -z");
        bool buildError = false;

        int nResultLines = 0;
        foreach( string line in res )
        {
            if( String.IsNullOrEmpty( line.Trim() ) )
            {
                continue;
            }

            Match match = Regex.Match( line, @"\s+\d+\s+(files? compiled|librar(y|ies) built|files? binplaced|executables? built)(?<error>.*)$" );
            if( match.Success )
            {
                nResultLines++;
                //Print( "***[{0}]\n", line );

                string possibleError = match.Groups[ "error" ].Value;
                //Print( "***+{0}+\n", possibleError );
                if( possibleError.Length > 0 )
                {
                    if( !Regex.IsMatch( possibleError, @"\s+\-\s+\d+\s+Error" ) )
                    {
                        Fatal( "Could not parse possible error string '{0}' in line '{1}'", possibleError, line );
                    }
                    buildError = true;
                }
            }
            else
            {
                if( nResultLines > 0 )
                {
                    Fatal( "Found non-result lines after a line that I interpreted as part of the final result: {0}", line );
                }
            }
        }

        if( buildError )
        {
            m_nBuildError++;
            Fatal( "ERROR: detected build error while building {0}\n", arch );
        } else if( nResultLines == 0 )
        {
            Fatal( "Could not validate success of build" );
        }

        //
        // Move the log file over to the release directory
        //
        string subDirNamePart = "";
        string subDirPath = "";
        if( subDir != "" )
        {
            subDirNamePart = subDir + @"_";
            subDirPath = subDir + @"\";
        }

        string chkfre = arch.Substring( arch.Length - 3, 3 );

        string LogFileName = subDirPath + "build" + chkfre + ".log";
        string DestFileName = @"release\buildlogs\" + subDirNamePart + "build" + arch + ".log";

        MoveFile( LogFileName, DestFileName );
    }




    public void CheckWindowsRazzleEnvironment()
    {
        Print( "Checking that we run in a Windows Razzle environment... " );

        string [] requiredVariables = new string[] {
                "PUBLIC_ROOT",
                "SDXROOT",
                "_NTROOT",
                "_NTDRIVE",
                };
        foreach( string s in requiredVariables )
        {
            if( !m_environment.Contains( s ) )
            {
                Fatal( "Could not find environment variable '{0}' which is expected in a Windows enlistment", s );
            }
        }

        Print( "Ok\n" );

    }

    public void CheckFilePresent( string filename )
    {
        if( !File.Exists( filename ) )
        {
            Fatal( "Could not find file '{0}'", filename );
        }
    }

    public void CheckSymCryptEnlistmentPresent()
    {
        Print( "Checking for presence of symcrypt enlistment in windows enlistment... " );
        m_SymCryptDir = m_environment[ "_NTDRIVE"] + (m_environment[ "_NTROOT" ] + @"\symcrypt");
        string currentDir = Directory.GetCurrentDirectory();

        if( String.Compare( m_SymCryptDir, currentDir, true ) != 0 )
        {
            Fatal( "ScBuild is not being run from the SymCrypt directory. \n" +
                "Current directory = {0}\n" +
                "Expected = {1}\n",
                currentDir, m_SymCryptDir );
        }

        CheckFilePresent( @"inc\symcrypt_internal_shared.inc" );
        CheckFilePresent( @"inc\symcrypt.h" );
        CheckFilePresent( @"lib\sc_lib.h" );

        Print( "Ok\n" );
    }

    public static IList RunStdout = ArrayList.Synchronized( new ArrayList() );
    public static IList RunStderr = ArrayList.Synchronized( new ArrayList() );


    public string CheckRelDirSynced( string relDir )
    // Returns the name of the current branch
    {
        string [] res = RunCmd( relDir, "git status ." );
        string branch = null;

        bool unSync = false;
        bool Sync = false;
        foreach( string resLine in res )
        {
            Match match = Regex.Match( resLine, @"^\s*On branch (?<branch>\S+)");
            // Print( "{0} -> {1}\n", resLine, match.Success );

            if( match.Success )
            {
                if( branch != null )
                {
                    Fatal( "Found two branch names, '{0}' and '{1}'", branch, match.Groups[ "branch" ].Value );
                }
                branch = match.Groups[ "branch" ].Value;
            }

            if( Regex.IsMatch( resLine, @"nothing to commit, working tree clean" ) )
            {
                Sync = true;
            }
            else if( Regex.IsMatch( resLine, @"untracked files present" ) ||
                     Regex.IsMatch( resLine, @"Changes to be committed" ) )
            {
                unSync = true;
            }
        }

        if( unSync )
        {
            if( m_option_ignore_sync )
            {
                Print( "...ignoring directory '{0}' not in sync\n", relDir );
            }
            else
            {
                Fatal( "Directory '{0}' is not in sync", relDir );
            }
        }

        if( !Sync )
        {
            if( m_option_ignore_sync )
            {
                // No point in printing another warning if we already did one.
                if( !unSync )
                {
                    Print( "...ignoring directory '{0}' not validated as sync'd\n", relDir );
                }
            }
            else
            {
                Fatal( "Could not validate/recognize that directory '{0}' is in sync", relDir );
            }
        }

        return branch;
    }

    void CheckToolsSynced()
    {
        // Removed this check as it does not work on Git enlistments.
        // We build Git from a Git repo enlisted in parallel to an OS repo, and use
        // the OS tools. We don't even know what branch the OS repo is on.
        // We have few tool changes anyway, so we drop this check.
    }

    string CheckSymCryptSynced()
    {
        string branch =  CheckRelDirSynced( "." );

        Print( "Using branch '{0}'\n", branch );

        return branch;
    }

    void CheckWriteableFiles()
    {
        // This code is no longer used as on Git all files are writable.
        // Keeping the code for now in case we need it

        Debug.Assert( false );

        string [] res = RunCmd( "", "dir /a-r-d /s /b" );

        foreach( string r in res )
        {
            string Line = r.ToLower();
            int i = Line.LastIndexOf( '\\' );
            if( i < 0 )
            {
                Fatal( "Did not find path separator in DIR output" );
            }
            string FileName = Line.Substring( i+1, Line.Length - i - 1 );

            if(
                !Line.Contains( @"symcrypt\release" ) &&
                FileName != "buildchk.log" &&
                FileName != "buildchk.err" &&
                FileName != "buildfre.log" &&
                FileName != "buildfre.err" &&
                FileName != "buildchk.trc" &&
                FileName != "buildfre.trc" &&
                FileName != "buildchk.prf" &&
                FileName != "buildfre.prf" &&
                FileName != "buildchk.wrn" &&
                FileName != "buildfre.wrn" &&
                FileName != "buildchk.dbb" &&
                FileName != "buildfre.dbb" &&
                FileName != "buildchk.evt" &&
                FileName != "buildfre.evt" &&
                FileName != "buildchk.metadata" &&
                FileName != "buildfre.metadata" &&
                FileName != "scbuild.log"
                )
            {
                if( m_option_ignore_writable )
                {
                    Print( "...ignoring writable file {0}\n", Line );
                } else
                {
                    Fatal( "Unknown writable file '{0}' found", Line );
                }
            }
        }
    }

    int m_apiVersion = -1;
    int m_minorVersion = -1;

    void UpdateVersionNumber()
    {
        string versionFileName = @"inc\symcrypt_internal_shared.inc";

        string [] lines = File.ReadAllLines( versionFileName );
        if( lines.Length < 10 )
        {
            Fatal( "Could not read file '{0}'", versionFileName );
        }

        int vApi = -1;
        int nApi = 0;
        int vMinor = -1;
        int nMinor = 0;
        int newApi = -1;
        int newMinor = -1;
        for( int i=0; i<lines.Length; i++ )
        {
            string line = lines[i];
            if( line.Contains( "SYMCRYPT_CODE_VERSION_API" ) )
            {
                MatchCollection matches = Regex.Matches( line, @"\d+" );
                if( matches.Count != 1 )
                {
                    Fatal( "Did not find a single integer in a Release version line '{0}'", line );
                }
                Match m = matches[0];
                string digits = m.Value;
                int apiVersion = Convert.ToInt32( digits );

                if( vApi >= 0 && vApi != apiVersion )
                {
                    Fatal( "Inconsistent API versions in symcrypt_internal_shared.inc({0}) : {1} {2}", line, vApi, apiVersion );
                }
                vApi = apiVersion;
                newApi = vApi;
                //if( false  )        // never auto-increment API version #
                //{
                //    newApi++;
                //    line = line.Replace( digits, newApi.ToString() );
                //    lines[i] = line;
                //}
                nApi++;
            }

            if( line.Contains( "SYMCRYPT_CODE_VERSION_MINOR" ) )
            {
                MatchCollection matches = Regex.Matches( line, @"\d+" );
                if( matches.Count != 1 )
                {
                    Fatal( "Did not find a single integer in a minor version line '{0}'", line );
                }
                Match m = matches[0];
                string digits = m.Value;
                int minorVersion = Convert.ToInt32( digits );

                if( vMinor >= 0 && vMinor != minorVersion )
                {
                    Fatal( "Inconsistent minor versions in symcrypt_internal_shared.inc file" );
                }
                vMinor = minorVersion;

                newMinor = vMinor;
                if( m_option_inc_version )
                {
                    newMinor = vMinor + 1;
                    line = line.Replace( digits, newMinor.ToString() );
                    lines[i] = line;
                }

                nMinor++;
            }
        }

        if( nApi != 1 || nMinor != 1 )
        {
            Fatal( "symcrypt_internal_shared.inc file has unexpected number of API and minor version-containing lines" );
        }

        foreach( string l in lines )
        {
            //Print( l + "\n" );
        }

        m_apiVersion = newApi;
        m_minorVersion = newMinor;

        if( !m_option_inc_version )
        {
            Print( "...Not updating version number\n" );
            return;
        }

        Print( "New SymCrypt version number {0}.{1}\n", newApi, newMinor );

        File.WriteAllLines(versionFileName, lines);

        // We do not commit any data so that we can always build without touching the repo state.
    }


    public void CopySymCryptToReleaseDir( string arch )
    {
        // We have to construct our own object_root as the copy command runs in the environment
        // of the razzle that called scbuild, not the razzle that builds the flavour.
        // string object_root = "" + m_environment["_NTBINDRIVE"] + m_environment[ "_NTROOT" ] + ".obj." + arch;
        string object_root = "" + m_environment["OSBuildRoot"] + @"\obj\" + arch;
        string libFileName = object_root + @"\symcrypt\lib\" + objDirName( arch ) + "symcrypt.lib";
        CopyFile( libFileName, @"release\lib\" + arch + @"\symcrypt.lib" );

        string testFileName = object_root + @"\symcrypt\unittest\exe_test\" + objDirName(arch) + "symcryptunittest";
        CopyFile(testFileName + ".exe", @"release\lib\" + arch + @"\symcryptunittest.exe");
        CopyFile(testFileName + ".pdb", @"release\lib\" + arch + @"\symcryptunittest.pdb");

        string testFileName2 = object_root + @"\symcrypt\unittest\exe_win7nlater\" + objDirName(arch) + "symcryptunittest_win7nlater";
        CopyFile(testFileName2 + ".exe", @"release\lib\" + arch + @"\symcryptunittest_win7nlater.exe");
        CopyFile(testFileName2 + ".pdb", @"release\lib\" + arch + @"\symcryptunittest_win7nlater.pdb");

        string testFileName3 = object_root + @"\symcrypt\unittest\exe_win8_1nlater\" + objDirName(arch) + "symcryptunittest_win8_1nlater";
        CopyFile(testFileName3 + ".exe", @"release\lib\" + arch + @"\symcryptunittest_win8_1nlater.exe");
        CopyFile(testFileName3 + ".pdb", @"release\lib\" + arch + @"\symcryptunittest_win8_1nlater.pdb");

        string testFileName4 = object_root + @"\symcrypt\unittest\exe_legacy\" + objDirName(arch) + "symcryptunittest_legacy";
        CopyFile(testFileName4 + ".exe", @"release\lib\" + arch + @"\symcryptunittest_legacy.exe");
        CopyFile(testFileName4 + ".pdb", @"release\lib\" + arch + @"\symcryptunittest_legacy.pdb");

        string testFileName5 = object_root + @"\symcrypt\unittest\module_windows\" + objDirName(arch) + "symcrypttestmodule";
        CopyFile(testFileName5 + ".dll", @"release\lib\" + arch + @"\symcrypttestmodule.dll");
        CopyFile(testFileName5 + ".pdb", @"release\lib\" + arch + @"\symcrypttestmodule.pdb");

        string testFileName6 = object_root + @"\symcrypt\unittest\module_windows_sys_um\" + objDirName(arch) + "SymCryptKernelTestModule_UM";
        CopyFile(testFileName6 + ".dll", @"release\lib\" + arch + @"\SymCryptKernelTestModule_UM.dll");
        CopyFile(testFileName6 + ".pdb", @"release\lib\" + arch + @"\SymCryptKernelTestModule_UM.pdb");

        string testFileName7 = object_root + @"\symcrypt\unittest\module_windows_sys_km\" + objDirName(arch) + "SymCryptKernelTestModule";
        CopyFile(testFileName7 + ".sys", @"release\lib\" + arch + @"\SymCryptKernelTestModule.sys");
        CopyFile(testFileName7 + ".pdb", @"release\lib\" + arch + @"\SymCryptKernelTestModule.pdb");
    }

    public string objDirName( string arch )
    {
        string cpu = arch.Substring( 0, arch.Length - 3 );
        string cpudir = (cpu != "x86") ? cpu : "i386";
        string chkfre = arch.Substring( arch.Length - 3, 3 );

        return "obj" + chkfre + @"\" + cpudir + @"\";
    }

    public void RunSymCryptTest( string arch )
    {
        // string object_root = m_environment[ "BASEDIR" ] + ".obj." + arch;
        string object_root = "" + m_environment["OSBuildRoot"] + @"\obj\" + arch;
        string cpu = arch.Substring( 0, arch.Length - 3 );
        string cpudir = (cpu != "x86") ? cpu : "i386";

        if( arch.StartsWith( "x86" ) || arch.StartsWith( "amd64" ) )
        {
            string command = @"release\lib\" + arch + @"\" + @"symcryptunittest";
            // Use the savexmmnofail option only somtimes
            if( m_random.Next(2) == 0 )
            {
                command += " -savexmmnofail";
            }
            string [] res = RunCmd( "", command );
            if( res.Length == 0 )
            {
                Fatal( "No output detected from running SymCryptUnitTest" );
            }
            if( !Regex.IsMatch( res[ res.Length - 1 ], "...SymCrypt unit test done" ) )
            {
                Fatal( "Did not detect that SymCrypt unit test succeeded" );
            }
        }
    }

    public void BuildAndUnitTest()
    {
        string [] flavors = m_option_flavors;
        if( flavors == null )
        {
            flavors = m_all_flavors;
        }

        foreach( string flavor in flavors )
        {
            Build( "", flavor );
            CopySymCryptToReleaseDir( flavor );
        }

        if( m_nBuildError > 0 )
        {
            Fatal( "One or more build errors occurred" );
        }

        foreach( string flavor in flavors )
        {
            RunSymCryptTest( flavor );
        }
    }


    bool m_option_release = false;
    bool m_option_test = false;

    string [] m_option_flavors = null;
    static string [] m_all_flavors = new string [] {
                                                        "amd64chk", "amd64fre",
                                                        "x86chk", "x86fre",
                                                        "arm64chk", "arm64fre",
                                                        "armchk", "armfre",
                                                    };

    bool m_option_inc_version = false;
    bool m_option_no_tag = false;

    bool m_option_ignore_sync = false;
    bool m_option_ignore_writable = false;

    string m_argumentsString = "";  // normalized argument string

    public bool ProcessOptions( string [] args )
    {
        for( int i=0; i<args.Length; i++ )
        {
            string opt = args[i].ToLower();

            m_argumentsString = m_argumentsString + " " + opt;

            if (opt == "-r")
            {
                m_option_release = true;
            }

            else if (opt == "-t")
            {
                m_option_test = true;
                ProcessOptions(new string[] { "-i", });
            }

            else if (opt.StartsWith("-i"))
            {
                if (opt.Length == 2)
                {
                    ProcessOptions(new string[] { "-is", });
                }
                else
                {
                    for (int j = 2; j < opt.Length; j++)
                    {
                        switch (opt[j])
                        {
                            case 's': m_option_ignore_sync = true; break;
                            // case 'w': m_option_ignore_writable = true; break;
                            default: Fatal("Unknown ignore letter {0} in option {1}", opt[j], opt); break;
                        }
                    }
                }
            }
            else if (opt.StartsWith("-f"))
            {
                string[] fls = opt.Substring(2, opt.Length - 2).Split(new Char[] { ',' });
                foreach (string fl in fls)
                {
                    if (Array.IndexOf(m_all_flavors, fl) < 0)
                    {
                        Fatal("Unrecognized flavor '{0}' in option '{1}'", fl, opt);
                    }
                }
                m_option_flavors = fls;
            }
            else if (opt == "-version" )
            {
                m_option_inc_version = true;
            }
            else if (opt == "-notag" )
            {
                m_option_no_tag = true;
            }
            else
            {
                Usage();
                return false;
            }
        }

        return true;
    }

    int BoolToInt(bool b)
    {
        if (b)
        {
            return 1;
        }
        return 0;
    }

    public void CheckOptionConsistency()
    {
        if (BoolToInt(m_option_release) + BoolToInt(m_option_test) == 0)
        {
            ProcessOptions( new string [] {"-t"} );
        }
        if (BoolToInt(m_option_release) + BoolToInt(m_option_test) != 1)
        {
            Fatal("Cannot specify more than one of -r -t");
        }
    }

    public void Usage()
    {
        Print( "Usage: scbuild <options...>\n"
            + "Options:\n"
            + "-r          Build a release version (checks for open files/create tag)\n"
            + "-t          Build a test version (default)\n"
            + "-is         Ignore Sync issues\n"
            + "                -i is equivalent to -is\n"
            + "-f<...>     Specify flavors to build in comma-separated list\n"
            + "            Flavors: x86chk, x86fre, amd64chk, amd64fre, armchk, armfre,\n"
            + "                arm64chk, arm64fre\n"
            + "-notag      Skip tag creation\n"
            + "-version    Increment the minor version in inc\\symcrypt_internal_shared.inc\n"
            );
    }

    public void CreateGitTag( string tagName )
    {
        // Our code still used 'label' in many places, as that is the tag concept in Source Depot
        if( !m_option_release || m_option_no_tag )
        {
            return;
        }

        if( m_option_ignore_sync )
        {
            Print( "Label creation disabled while any -i option is used\n" );
            return;
        }

        string [] res;
        res = RunCmd( "", "git tag -a -m \"Creation of "+ tagName + ".cab\" " + tagName );

        if( res.Length != 0 )
        {
            Fatal("Unexpected output from tag command");
        }

        res = RunCmd("", "git tag -l " + tagName);
        if( res.Length != 1 || !Regex.IsMatch( res[0], tagName) )
        {
            Fatal("Could not verify that tag was properly created");
        }

        bool pushOk = false;
        res = RunCmd( "", "git push origin " + tagName );
        foreach( string line in res )
        {
            if( Regex.IsMatch( line, "new tag.*" + tagName ))
            {
                pushOk = true;
            }
        }
        if( !pushOk )
        {
            Fatal( "Could not verify that tag was pushed to remote" );
        }
    }

    public string GetCommitInfo()
    {
        string [] reslines = RunCmd( ".", @"git log -n 1 --date=iso-strict-local --format=%cd_%h" );
        string res = reslines[0];
        res = res.Trim();
        res = res.Replace( ":", "" );       // colons are not valid in file names
        return res;
    }


    public void CreateCab()
    {
        Print("Copying header files to release directory...\n");

        string[] filesToCopy = new string[] {
            @"symcrypt.h",
            @"symcrypt_low_level.h",
            @"symcrypt_internal.h",
            @"symcrypt_internal_shared.inc",
        };

        foreach (string file in filesToCopy)
        {
            CopyFile(@"inc\" + file, @"release\inc\" + file);
        }

        Print( "Closing log file and creating CAB...\n" );

        Print( "Current time = {0}\n", DateTime.Now.ToString( LogDateTimeFormat ) );

        Output.CloseLogFile();
        MoveFile( "scbuild.log", @"release\scbuild.log" );

        if( m_apiVersion < 0 || m_minorVersion < 0 )
        {
            Fatal( "Cannot generate CAB file without version number {0} {1}", m_apiVersion, m_minorVersion );
        }

        string fileNameWarning = "";
        if( m_option_flavors != null ||
            m_option_ignore_sync ||
            m_option_inc_version ||
            !m_option_release
            )
        {
            fileNameWarning = "_not_for_release";
        }

        string releaseName = "SymCrypt" + fileNameWarning + "_v" + m_apiVersion + "." + m_minorVersion + "_" + m_currentBranch + "_" + GetCommitInfo();
        string cabFileName =  releaseName + ".cab";

        string [] res = RunCmd( "release", "cabarc -r -p n " + cabFileName + " *.*" );
        if( !Regex.IsMatch( res[ res.Length - 1 ], "Completed successfully" ) )
        {
            Fatal( "Could not validate success of cab creation" );
        }

        CreateGitTag( releaseName );
    }

    public void CleanReleaseDirectory()
    {
        string [] res = RunCmd( "", @"rmdir ..\symcrypt\release /s /q" );

        if( res.Length != 0 )
        {
            if( res.Length != 1 || res[0] != "* The system cannot find the file specified." )
            {
                Fatal( "Unexpected output from the rmdir command: " + res[0] );
            }
        }

        string [] directoriesToCreate = new string[] {
            @"release",
            @"release\buildlogs",
            @"release\lib\amd64chk",
            @"release\lib\amd64fre",
            @"release\lib\x86chk",
            @"release\lib\x86fre",
            @"release\lib\armchk",
            @"release\lib\armfre",
            @"release\lib\arm64chk",
            @"release\lib\arm64fre",
            @"release\inc",
        };

        foreach( string dir in directoriesToCreate )
        {
            res = RunCmd( "", "mkdir " + dir );
            if( res.Length != 0 )
            {
                Fatal( "Unexpected output from mkdir command" );
            }
        }
    }

    public ScBuild( string [] args )
    {

        m_environment = System.Environment.GetEnvironmentVariables();

        Output.OpenLogFile( "ScBuild.log" );

        Print( "> ScBuild" );
        foreach( string arg in args )
        {
            Print( " {0}", arg );
        }
        Print( "\n" );

        Print( "SymCrypt build tool version 1.0\n");

        Print( "Start time = {0}\n", DateTime.Now.ToString( LogDateTimeFormat ) );

        m_random = new Random();

        if( !ProcessOptions( args ) )
        {
            return;
        }
        CheckOptionConsistency();

        CheckWindowsRazzleEnvironment();
        CheckSymCryptEnlistmentPresent();

        CheckToolsSynced();
        m_currentBranch = CheckSymCryptSynced();

        // In Git, all files are writable, so this check is not useful.
        // CheckWriteableFiles();

        CheckForBannedSymbols();

        UpdateVersionNumber();      // retrieve & update if needed

        if( m_option_inc_version )
        {
            // Incrementing the version # should be followed by a checkin of the new #,
            // so we don't build after the change.
            return;
        }

        CleanReleaseDirectory();

        // CreateGitTag();

        BuildAndUnitTest();

        CreateCab();

    }

    public static int Main( string[] args )
    {
        int res = 0;

        try
        {
            new ScBuild( args );
        } catch( Exception e )
        {
            Print( "FATAL ERROR: {0}\n", e );
            res = -1;
        }

        Output.CloseLogFile();

        return res;
    }
}


}


