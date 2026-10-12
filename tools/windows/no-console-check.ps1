<#
.SYNOPSIS
    Windows console checklist steps 14 and 19 (docs/M4_READINESS.md 14)
    with a bounded timeout, a console probe and diagnostic reporting.

.DESCRIPTION
    Test scratch data only. Runs each case in two launch modes:

    - NoWindow: System.Diagnostics.Process with UseShellExecute=false,
      CreateNoWindow=true, all three standard streams redirected and standard
      input closed at once (the launch described for the run of 2026-10-11
      at af6a4ce). CreateNoWindow sets CREATE_NO_WINDOW, which Microsoft
      documents as: "The process is a console application that is being run
      without a console window. Therefore, the console handle for the
      application is not set." Whether CONIN$ and CONOUT$ can nevertheless
      be opened in such a process is not established; this mode measures it.
    - Detached: CreateProcessW with DETACHED_PROCESS, standard input from an
      empty file and output to files. A console application started this way
      should have no console at all (DETACHED_PROCESS: the process "does not
      inherit its parent's console"); this mode measures that too.

    Before pvault runs, a probe program (compiled here from the source below)
    is started in the same mode and reports whether CONIN$ and CONOUT$ can be
    opened with the access and sharing pvault uses (terminal.rs, `open`),
    whether a console window and console processes exist, and the types of
    the standard handles. pvault decides "a terminal exists" exactly when
    both opens succeed.

    Every launch is bounded by -TimeoutSeconds; a process still running then
    is terminated (and its child processes), and the timeout is recorded.
    Nothing is deleted or overwritten: each run writes to a new folder under
    -OutRoot and refuses to start if that folder exists. Results are
    observations (expected and observed side by side); this script does not
    decide whether a checklist step passed.

    Requires Windows PowerShell 5.1 (powershell.exe); the probe is compiled
    with the .NET Framework C# compiler (csc.exe) that ships with Windows.

.EXAMPLE
    Task Scheduler action (with "Stop the task if it runs longer than" set to
    30 minutes as a second bound):
      Program:   powershell.exe
      Arguments: -NoProfile -NonInteractive -ExecutionPolicy Bypass -File
                 "C:\pvtest\no-console-check.ps1" -Pvault
                 "C:\src\pvault\target\release\pvault.exe" -OutRoot
                 "C:\pvtest\harness"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $Pvault,
    [Parameter(Mandatory = $true)] [string] $OutRoot,
    [ValidateRange(5, 600)] [int] $TimeoutSeconds = 60,
    [ValidateSet('NoWindow', 'Detached', 'Both')] [string] $Launch = 'Both',
    # Optional: the commit the binary was built from, recorded only.
    [string] $Commit = '',
    # Optional: a folder of earlier result files to fingerprint (SHA-256,
    # size, times). The files are only read, never changed or moved.
    [string] $EvidenceDir = ''
)

Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$run = Join-Path $OutRoot ('run-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
if (Test-Path -LiteralPath $run) {
    throw "The run folder $run already exists; nothing was changed."
}
New-Item -ItemType Directory -Path $run | Out-Null
$logFile = Join-Path $run 'log.txt'

function Write-Log([string] $Text) {
    $line = (Get-Date -Format 'o') + ' ' + $Text
    Add-Content -LiteralPath $logFile -Value $line -Encoding UTF8
}

function Save-Text([string] $Path, [string] $Text) {
    [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding($false)))
}

function Save-Json([string] $Path, $Object) {
    Save-Text $Path ($Object | ConvertTo-Json -Depth 6)
}

# Windows command-line quoting (the rules CommandLineToArgvW and the Rust
# runtime use to split arguments).
function ConvertTo-CommandLineArg([string] $Arg) {
    if ($Arg -ne '' -and $Arg -notmatch '[\s"]') { return $Arg }
    $sb = New-Object System.Text.StringBuilder
    [void] $sb.Append('"')
    $slashes = 0
    foreach ($c in $Arg.ToCharArray()) {
        if ($c -eq [char] '\') { $slashes++; continue }
        if ($c -eq [char] '"') {
            [void] $sb.Append('\' * (2 * $slashes + 1)); [void] $sb.Append('"'); $slashes = 0; continue
        }
        if ($slashes -gt 0) { [void] $sb.Append('\' * $slashes); $slashes = 0 }
        [void] $sb.Append($c)
    }
    [void] $sb.Append('\' * (2 * $slashes)); [void] $sb.Append('"')
    return $sb.ToString()
}

function Join-CommandLine([string[]] $Items) {
    return (($Items | ForEach-Object { ConvertTo-CommandLineArg $_ }) -join ' ')
}

$probeSource = @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class PvConsoleProbe
{
    const uint GENERIC_READ = 0x80000000, GENERIC_WRITE = 0x40000000;
    const uint FILE_SHARE_READ = 1, FILE_SHARE_WRITE = 2, OPEN_EXISTING = 3;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sa,
        uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")]
    static extern IntPtr GetConsoleWindow();
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint GetConsoleProcessList(uint[] list, uint count);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetStdHandle(int which);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint GetFileType(IntPtr h);

    // The same access, sharing and disposition as pvault's `open`.
    static string Open(string name)
    {
        IntPtr h = CreateFileW(name, GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        if (h == new IntPtr(-1)) return "error " + Marshal.GetLastWin32Error();
        CloseHandle(h);
        return "ok";
    }

    static string HandleType(int which)
    {
        IntPtr h = GetStdHandle(which);
        if (h == IntPtr.Zero) return "none";
        if (h == new IntPtr(-1)) return "invalid";
        switch (GetFileType(h))
        {
            case 1: return "disk";
            case 2: return "char";
            case 3: return "pipe";
            default: return "unknown";
        }
    }

    public static string Describe()
    {
        StringBuilder sb = new StringBuilder();
        sb.AppendLine("conin=" + Open("CONIN$"));
        sb.AppendLine("conout=" + Open("CONOUT$"));
        sb.AppendLine("console_window=0x" + GetConsoleWindow().ToInt64().ToString("x"));
        uint[] list = new uint[64];
        uint n = GetConsoleProcessList(list, 64);
        sb.AppendLine("console_process_count=" +
            (n == 0 ? "error " + Marshal.GetLastWin32Error() : n.ToString()));
        sb.AppendLine("stdin_type=" + HandleType(-10));
        sb.AppendLine("stdout_type=" + HandleType(-11));
        sb.AppendLine("stderr_type=" + HandleType(-12));
        sb.AppendLine("session_id=" + System.Diagnostics.Process.GetCurrentProcess().SessionId);
        sb.AppendLine("user_interactive=" + Environment.UserInteractive);
        return sb.ToString();
    }

    public static int Main()
    {
        Console.Out.Write(Describe());
        Console.Out.Flush();
        return 0;
    }
}
'@

$launcherSource = @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public class PvLaunchResult
{
    public int Pid;
    public bool TimedOut;
    public long ExitCode = -1;
    public string Error = "";
}

public static class PvDetachedLauncher
{
    const uint GENERIC_READ = 0x80000000, GENERIC_WRITE = 0x40000000;
    const uint FILE_SHARE_READ = 1, OPEN_EXISTING = 3, CREATE_NEW = 1;
    const uint DETACHED_PROCESS = 0x00000008;
    const int STARTF_USESTDHANDLES = 0x00000100;
    const uint WAIT_OBJECT_0 = 0, WAIT_TIMEOUT = 0x102;

    [StructLayout(LayoutKind.Sequential)]
    struct SECURITY_ATTRIBUTES { public int nLength; public IntPtr lpSecurityDescriptor; public int bInheritHandle; }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO
    {
        public int cb; public string lpReserved; public string lpDesktop; public string lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreateFileW(string name, uint access, uint share, ref SECURITY_ATTRIBUTES sa,
        uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcessW(string app, StringBuilder cmd, IntPtr pa, IntPtr ta, bool inherit,
        uint flags, IntPtr env, string cwd, ref STARTUPINFO si, out PROCESS_INFORMATION pi);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint WaitForSingleObject(IntPtr h, uint ms);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetExitCodeProcess(IntPtr h, out uint code);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool TerminateProcess(IntPtr h, uint code);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr h);

    static IntPtr OpenInheritable(string path, uint access, uint disposition)
    {
        SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
        sa.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
        sa.bInheritHandle = 1;
        IntPtr h = CreateFileW(path, access, FILE_SHARE_READ, ref sa, disposition, 0x80, IntPtr.Zero);
        if (h == new IntPtr(-1))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "CreateFileW " + path);
        return h;
    }

    // Starts `commandLine` with no console (DETACHED_PROCESS), standard input
    // from `stdinPath` and output to two new files; waits at most
    // `timeoutMs`, then terminates the process. Never throws: failures are
    // returned in Error.
    public static PvLaunchResult Run(string exe, string commandLine, string stdinPath,
        string stdoutPath, string stderrPath, int timeoutMs)
    {
        PvLaunchResult r = new PvLaunchResult();
        IntPtr hin = IntPtr.Zero, hout = IntPtr.Zero, herr = IntPtr.Zero;
        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
        try
        {
            hin = OpenInheritable(stdinPath, GENERIC_READ, OPEN_EXISTING);
            hout = OpenInheritable(stdoutPath, GENERIC_WRITE, CREATE_NEW);
            herr = OpenInheritable(stderrPath, GENERIC_WRITE, CREATE_NEW);
            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(typeof(STARTUPINFO));
            si.dwFlags = STARTF_USESTDHANDLES;
            si.hStdInput = hin; si.hStdOutput = hout; si.hStdError = herr;
            if (!CreateProcessW(exe, new StringBuilder(commandLine), IntPtr.Zero, IntPtr.Zero, true,
                    DETACHED_PROCESS, IntPtr.Zero, null, ref si, out pi))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "CreateProcessW");
            r.Pid = pi.dwProcessId;
            uint wait = WaitForSingleObject(pi.hProcess, (uint) timeoutMs);
            if (wait == WAIT_TIMEOUT)
            {
                r.TimedOut = true;
                TerminateProcess(pi.hProcess, 0xFFFFFFFF);
                WaitForSingleObject(pi.hProcess, 10000);
            }
            else if (wait != WAIT_OBJECT_0)
            {
                r.Error = "WaitForSingleObject returned " + wait + ", error " + Marshal.GetLastWin32Error();
            }
            uint code;
            if (GetExitCodeProcess(pi.hProcess, out code)) r.ExitCode = code;
        }
        catch (Exception e)
        {
            r.Error = e.GetType().Name + ": " + e.Message;
        }
        finally
        {
            if (pi.hThread != IntPtr.Zero) CloseHandle(pi.hThread);
            if (pi.hProcess != IntPtr.Zero) CloseHandle(pi.hProcess);
            if (hin != IntPtr.Zero) CloseHandle(hin);
            if (hout != IntPtr.Zero) CloseHandle(hout);
            if (herr != IntPtr.Zero) CloseHandle(herr);
        }
        return r;
    }
}
'@

# Child processes of `ProcessId` (for example conhost.exe, which hosts a
# console the process was given, or pvault's estimator child).
function Get-ChildProcessList([int] $ProcessId) {
    try {
        return @(Get-CimInstance Win32_Process -Filter "ParentProcessId=$ProcessId" |
            ForEach-Object { [ordered] @{ name = $_.Name; pid = $_.ProcessId } })
    } catch {
        return @([ordered] @{ error = $_.Exception.Message })
    }
}

function Stop-ChildProcesses([int] $ProcessId) {
    $stopped = @()
    foreach ($c in Get-ChildProcessList $ProcessId) {
        if ($c.Contains('pid')) {
            try { Stop-Process -Id $c.pid -Force -ErrorAction Stop; $stopped += $c }
            catch { $stopped += [ordered] @{ name = $c.name; pid = $c.pid; error = $_.Exception.Message } }
        }
    }
    return $stopped
}

function Get-PathState([hashtable] $Paths) {
    $state = [ordered] @{}
    foreach ($k in ($Paths.Keys | Sort-Object)) {
        $p = $Paths[$k]
        $entry = [ordered] @{ path = $p; exists = (Test-Path -LiteralPath $p) }
        if ($entry.exists -and (Test-Path -LiteralPath $p -PathType Container)) {
            $entry.entries = @(Get-ChildItem -LiteralPath $p -Force -Recurse |
                ForEach-Object { $_.FullName.Substring($p.Length) })
        }
        $state[$k] = $entry
    }
    return $state
}

# One launch in one mode. Never throws: launch and harness errors are
# recorded in the result.
function Invoke-Case([string] $Mode, [string] $Exe, [string[]] $Arguments, [string] $Dir,
                     [hashtable] $Paths, [string] $ConfigDir) {
    $stdoutFile = Join-Path $Dir 'stdout.txt'
    $stderrFile = Join-Path $Dir 'stderr.txt'
    $commandLine = Join-CommandLine $Arguments
    $result = [ordered] @{
        mode = $Mode; exe = $Exe; arguments = $Arguments; timeout_seconds = $TimeoutSeconds
        pvault_config_dir = $ConfigDir
        before = (Get-PathState $Paths)
    }
    $previousConfig = $env:PVAULT_CONFIG_DIR
    $env:PVAULT_CONFIG_DIR = $ConfigDir
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        if ($Mode -eq 'NoWindow') {
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = $Exe
            $psi.Arguments = $commandLine
            $psi.UseShellExecute = $false
            $psi.CreateNoWindow = $true
            $psi.RedirectStandardInput = $true
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
            $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8
            $p = [System.Diagnostics.Process]::Start($psi)
            $result.pid = $p.Id
            $p.StandardInput.Close()
            # Read both pipes concurrently, so a full pipe cannot stall the
            # child or this script.
            $outTask = $p.StandardOutput.ReadToEndAsync()
            $errTask = $p.StandardError.ReadToEndAsync()
            Start-Sleep -Milliseconds 500
            $result.children_after_start = Get-ChildProcessList $p.Id
            if ($p.WaitForExit($TimeoutSeconds * 1000)) {
                $p.WaitForExit()
                $result.timed_out = $false
                $result.exit_code = $p.ExitCode
            } else {
                $result.timed_out = $true
                $result.children_at_timeout = Get-ChildProcessList $p.Id
                $result.children_stopped = Stop-ChildProcesses $p.Id
                try { $p.Kill() } catch { $result.kill_error = $_.Exception.Message }
                $result.exited_after_kill = $p.WaitForExit(10000)
                if ($result.exited_after_kill) { $result.exit_code = $p.ExitCode }
            }
            $result.stdout_read = $outTask.Wait(10000)
            $result.stderr_read = $errTask.Wait(10000)
            Save-Text $stdoutFile ($(if ($result.stdout_read) { $outTask.Result } else { '(not read within 10 s)' }))
            Save-Text $stderrFile ($(if ($result.stderr_read) { $errTask.Result } else { '(not read within 10 s)' }))
        } else {
            $stdinFile = Join-Path $Dir 'stdin-empty.txt'
            Save-Text $stdinFile ''
            $fullLine = (ConvertTo-CommandLineArg $Exe) + ' ' + $commandLine
            $r = [PvDetachedLauncher]::Run($Exe, $fullLine, $stdinFile, $stdoutFile, $stderrFile,
                $TimeoutSeconds * 1000)
            $result.pid = $r.Pid
            $result.timed_out = $r.TimedOut
            $result.exit_code = $r.ExitCode
            if ($r.Error) { $result.launch_error = $r.Error }
            if ($r.Pid) { $result.children_stopped = Stop-ChildProcesses $r.Pid }
        }
    } catch {
        $result.harness_error = [ordered] @{
            type = $_.Exception.GetType().FullName
            message = $_.Exception.Message
            at = $_.InvocationInfo.PositionMessage
        }
    } finally {
        $env:PVAULT_CONFIG_DIR = $previousConfig
    }
    $result.seconds = [math]::Round($watch.Elapsed.TotalSeconds, 2)
    $result.after = Get-PathState $Paths
    Save-Json (Join-Path $Dir 'result.json') $result
    $status = if ($result.Contains('harness_error')) { 'harness error' }
              elseif ($result.Contains('launch_error')) { 'launch error' }
              elseif ($result.timed_out) { 'TIMED OUT' }
              else { 'exit ' + $result.exit_code }
    Write-Log ("{0} {1}: {2} after {3} s" -f $Mode, (Split-Path $Dir -Leaf), $status, $result.seconds)
    return $result
}

$harnessExit = 0
$summary = New-Object System.Collections.Generic.List[string]
try {
    if ($PSVersionTable.PSEdition -ne 'Desktop') {
        throw 'Run this with Windows PowerShell 5.1 (powershell.exe), not PowerShell 7.'
    }
    $Pvault = (Resolve-Path -LiteralPath $Pvault).Path
    Write-Log "run folder $run"

    $os = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $osText = (@('ProductName', 'DisplayVersion', 'CurrentBuild', 'UBR') | ForEach-Object {
        $prop = $os.PSObject.Properties[$_]
        if ($prop) { "$_=$($prop.Value)" } else { "$_=(absent)" }
    }) -join ', '
    Add-Type -TypeDefinition $probeSource
    Add-Type -TypeDefinition $launcherSource
    # The probe must be a console-subsystem program, as pvault is.
    $probeCs = Join-Path $run 'console-probe.cs'
    $probeExe = Join-Path $run 'console-probe.exe'
    Save-Text $probeCs $probeSource
    $csc = Join-Path ([System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()) 'csc.exe'
    # Compiler messages on standard error must not stop the script here; the
    # exit code decides.
    $ErrorActionPreference = 'Continue'
    $cscOut = & $csc /nologo /target:exe "/out:$probeExe" $probeCs 2>&1 | Out-String
    $cscExit = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    Save-Text (Join-Path $run 'console-probe-build.txt') ("csc exit $cscExit`r`n" + $cscOut)
    if ($cscExit -ne 0 -or -not (Test-Path -LiteralPath $probeExe)) {
        throw "Compiling the console probe failed (csc exit $cscExit): $cscOut"
    }
    $environment = [ordered] @{
        started = (Get-Date -Format 'o')
        user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        harness_session_id = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
        harness_user_interactive = [Environment]::UserInteractive
        windows = $osText
        powershell = $PSVersionTable.PSVersion.ToString()
        pvault = $Pvault
        pvault_sha256 = (Get-FileHash -LiteralPath $Pvault -Algorithm SHA256).Hash
        pvault_modified = (Get-Item -LiteralPath $Pvault).LastWriteTimeUtc.ToString('o')
        commit = $Commit
        timeout_seconds = $TimeoutSeconds
        harness_console = ([PvConsoleProbe]::Describe() -split "`r?`n" | Where-Object { $_ })
    }
    Save-Json (Join-Path $run 'environment.json') $environment

    if ($EvidenceDir) {
        $evidence = @(Get-ChildItem -LiteralPath $EvidenceDir -Recurse -File -Force | ForEach-Object {
            [ordered] @{
                path = $_.FullName; size = $_.Length
                modified_utc = $_.LastWriteTimeUtc.ToString('o')
                sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
            }
        })
        Save-Json (Join-Path $run 'evidence-fingerprints.json') $evidence
        Write-Log ("fingerprinted {0} earlier files in {1} (read only)" -f $evidence.Count, $EvidenceDir)
    }

    $modes = if ($Launch -eq 'Both') { @('NoWindow', 'Detached') } else { @($Launch) }
    $all = New-Object System.Collections.Generic.List[object]
    foreach ($mode in $modes) {
        $modeDir = Join-Path $run $mode
        New-Item -ItemType Directory -Path $modeDir | Out-Null

        # The probe, in the same launch mode as pvault.
        $dir = Join-Path $modeDir 'probe'
        New-Item -ItemType Directory -Path $dir | Out-Null
        $probe = Invoke-Case $mode $probeExe @() $dir @{} (Join-Path $dir 'unused-settings')
        $all.Add($probe)
        $probeOut = Get-Content -LiteralPath (Join-Path $dir 'stdout.txt') -Raw -ErrorAction SilentlyContinue
        $probeLines = @($probeOut -split "`r?`n" | Where-Object { $_ })
        # The measured CONIN$ and CONOUT$ results ("ok" or "error <code>").
        $measured = [ordered] @{ mode = $mode; conin = '(not reported)'; conout = '(not reported)' }
        foreach ($line in $probeLines) {
            $kv = $line -split '=', 2
            if ($kv.Count -eq 2) { $measured[$kv[0]] = $kv[1] }
        }
        Save-Json (Join-Path $dir 'measured.json') $measured
        $summary.Add("[$mode] console probe: " + ($probeLines -join '; '))
        $summary.Add(("[$mode] measured: CONIN$ {0}, CONOUT$ {1}" -f $measured.conin, $measured.conout))

        # Step 14: PNG verification without a console.
        $dir = Join-Path $modeDir 'step14-png'
        $data = Join-Path $dir 'data'
        New-Item -ItemType Directory -Path (Join-Path $data 'cards') | Out-Null
        $paths = @{ vault = (Join-Path $data 'vault'); settings = (Join-Path $data 'settings');
                    cards = (Join-Path $data 'cards') }
        $r = Invoke-Case $mode $Pvault @('init', $paths.vault, '--mode', 'portable', '--cards', 'paper',
            '--cards-dir', $paths.cards, '--custom', '--secrets-stdin',
            '--card-a-png', (Join-Path $data 'a.png')) $dir $paths $paths.settings
        $all.Add($r)
        $summary.Add(("[$mode] step 14: expected exit 6, no vault or settings folder; observed {0}, vault {1}, settings {2}" -f
            $(if ($r.Contains('timed_out') -and $r.timed_out) { 'TIMEOUT' } elseif ($r.Contains('exit_code')) { 'exit ' + $r.exit_code } else { 'no exit code' }),
            $(if ($r.after.vault.exists) { 'exists' } else { 'absent' }),
            $(if ($r.after.settings.exists) { 'exists' } else { 'absent' })))

        # Step 19: digital cards without --accept-risk and without a console.
        $dir = Join-Path $modeDir 'step19-digital'
        $data = Join-Path $dir 'data'
        New-Item -ItemType Directory -Path (Join-Path $data 'card-a') | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $data 'card-b') | Out-Null
        $paths = @{ vault = (Join-Path $data 'vault'); settings = (Join-Path $data 'settings');
                    card_a = (Join-Path $data 'card-a'); card_b = (Join-Path $data 'card-b') }
        $r = Invoke-Case $mode $Pvault @('init', $paths.vault, '--mode', 'portable', '--cards', 'digital',
            '--card-a-dir', $paths.card_a, '--card-b-dir', $paths.card_b, '--custom', '--secrets-stdin') `
            $dir $paths $paths.settings
        $all.Add($r)
        $summary.Add(("[$mode] step 19: expected exit 4, no vault, settings or card file; observed {0}, vault {1}, settings {2}, card files {3}" -f
            $(if ($r.Contains('timed_out') -and $r.timed_out) { 'TIMEOUT' } elseif ($r.Contains('exit_code')) { 'exit ' + $r.exit_code } else { 'no exit code' }),
            $(if ($r.after.vault.exists) { 'exists' } else { 'absent' }),
            $(if ($r.after.settings.exists) { 'exists' } else { 'absent' }),
            (@($r.after.card_a.entries).Count + @($r.after.card_b.entries).Count)))
    }
    foreach ($res in $all) {
        if ($res.Contains('harness_error') -or $res.Contains('launch_error')) { $harnessExit = 3 }
        elseif ($res.Contains('timed_out') -and $res.timed_out -and $harnessExit -eq 0) { $harnessExit = 2 }
    }
} catch {
    $harnessExit = 3
    Save-Text (Join-Path $run 'error.txt') (($_ | Out-String) + "`r`n" + $_.ScriptStackTrace)
    Write-Log ('harness error: ' + $_.Exception.Message)
    $summary.Add('HARNESS ERROR: ' + $_.Exception.Message + ' (details in error.txt)')
} finally {
    $summary.Add("harness exit $harnessExit (0: every launch finished; 2: a launch timed out; 3: a harness or launch error)")
    Save-Text (Join-Path $run 'summary.txt') (($summary -join "`r`n") + "`r`n")
    Write-Log "finished, harness exit $harnessExit"
}
exit $harnessExit
