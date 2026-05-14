# Build the OpenSSL 3 style Tongsuo tree used only by the SM2+ML-KEM wrapper.
[CmdletBinding()]
param(
  [string]$ProjectRoot,
  [string]$SourceDir,
  [string]$BuildDir,
  [string]$Prefix = $env:TONGSUO_PQ_PREFIX,
  [string]$ConfigOpts = $env:TONGSUO_PQ_CONFIG_OPTS,
  [string]$InstallTargets = $env:TONGSUO_PQ_INSTALL_TARGETS,
  [string]$Target = $env:TONGSUO_PQ_TARGET,
  [switch]$NoBootstrap
)

$scriptDir = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($scriptDir)) {
  $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
}
$repoRootDefault = Split-Path -Parent $scriptDir
if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
  $ProjectRoot = $repoRootDefault
}
$repoRoot = $ProjectRoot

if ([string]::IsNullOrWhiteSpace($SourceDir)) {
  $SourceDir = Join-Path $repoRoot "third_party\Tongsuo-master"
}
if ([string]::IsNullOrWhiteSpace($BuildDir)) {
  $BuildDir = Join-Path $repoRoot "third_party\tongsuo-pq-build"
}
if ([string]::IsNullOrWhiteSpace($Prefix)) {
  $Prefix = Join-Path $repoRoot "third_party\tongsuo-pq-install"
}
if ([string]::IsNullOrWhiteSpace($ConfigOpts)) {
  $ConfigOpts = "enable-ntls shared"
}
if ([string]::IsNullOrWhiteSpace($InstallTargets)) {
  $InstallTargets = "install_sw"
}
if ([string]::IsNullOrWhiteSpace($Target)) {
  $Target = "VC-WIN64A"
}

function Test-DevEnv {
  return ((Get-Command nmake -ErrorAction SilentlyContinue) -and
          (Get-Command cl -ErrorAction SilentlyContinue))
}

function Set-WorkspaceTemp {
  $tempDir = Join-Path $repoRoot ".worktree\tmp"
  New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
  $resolvedTempDir = (Resolve-Path -LiteralPath $tempDir).Path
  $env:TEMP = $resolvedTempDir
  $env:TMP = $resolvedTempDir
}

function Find-VsDevCmd {
  $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
  if (Test-Path -LiteralPath $vswhere) {
    $vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($vsPath) {
      $candidate = Join-Path $vsPath "Common7\Tools\VsDevCmd.bat"
      if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
  }
  foreach ($candidate in @(
    "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat",
    "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat",
    "C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat",
    "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\VsDevCmd.bat"
  )) {
    if (Test-Path -LiteralPath $candidate) { return $candidate }
  }
  return $null
}

function Get-PowerShellPath {
  try {
    $p = (Get-Process -Id $PID).Path
    if ($p) { return $p }
  } catch {}
  return "powershell.exe"
}

function Invoke-InDevCmd {
  param([string]$VsDevCmdPath)

  $psExe = Get-PowerShellPath
  $args = @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", "`"$PSCommandPath`"",
    "-ProjectRoot", "`"$ProjectRoot`"",
    "-SourceDir", "`"$SourceDir`"",
    "-BuildDir", "`"$BuildDir`"",
    "-Prefix", "`"$Prefix`"",
    "-ConfigOpts", "`"$ConfigOpts`"",
    "-InstallTargets", "`"$InstallTargets`"",
    "-Target", "`"$Target`"",
    "-NoBootstrap"
  )
  cmd /c "`"$VsDevCmdPath`" -arch=amd64 -host_arch=amd64 && `"$psExe`" $($args -join ' ')"
  exit $LASTEXITCODE
}

if (-not (Test-Path -LiteralPath $SourceDir)) {
  Write-Error "Tongsuo PQ source not found at $SourceDir"
  exit 1
}

Set-WorkspaceTemp

if (-not $NoBootstrap -and -not (Test-DevEnv)) {
  $vsDevCmd = Find-VsDevCmd
  if (-not $vsDevCmd) {
    Write-Error "MSVC build tools not found. Open a Developer Command Prompt for Visual Studio and retry."
    exit 1
  }
  Invoke-InDevCmd -VsDevCmdPath $vsDevCmd
}

if (-not (Get-Command perl -ErrorAction SilentlyContinue)) {
  Write-Error "perl not found. Install Perl 5 and retry."
  exit 1
}
if (-not (Get-Command nmake -ErrorAction SilentlyContinue)) {
  Write-Error "nmake not found. Open a Developer Command Prompt for Visual Studio and retry."
  exit 1
}

New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null

$openSSLDir = Join-Path $Prefix "ssl"
Push-Location $BuildDir
try {
  $cfgArgs = @($Target)
  $cfgArgs += ($ConfigOpts -split '\s+' | Where-Object { $_ -ne "" })
  $cfgArgs += "--prefix=$Prefix"
  $cfgArgs += "--openssldir=$openSSLDir"

  & perl (Join-Path $SourceDir "Configure") @cfgArgs
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

  & nmake
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

  foreach ($targetName in ($InstallTargets -split '\s+' | Where-Object { $_ -ne "" })) {
    & nmake $targetName
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
  }
}
finally {
  Pop-Location
}

$wrapperDir = Join-Path $repoRoot "crypto\sm2mlkem"
$nativeSource = Join-Path $wrapperDir "native\wrapper.c"
$includeDir = Join-Path $Prefix "include"
$libDir = Join-Path $Prefix "lib"
$cryptoLib = Join-Path $libDir "libcrypto.lib"
if (-not (Test-Path -LiteralPath $cryptoLib)) {
  $cryptoLib = Join-Path $libDir "crypto.lib"
}
if (-not (Test-Path -LiteralPath $cryptoLib)) {
  Write-Error "libcrypto import library not found under $libDir"
  exit 1
}

$dllOut = Join-Path $wrapperDir "sm2mlkem_wrapper.dll"
$implibOut = Join-Path $wrapperDir "sm2mlkem_wrapper.lib"
$wrapperBuildDir = Join-Path $BuildDir "sm2mlkem-wrapper"
$wrapperObj = Join-Path $wrapperBuildDir "wrapper.obj"

New-Item -ItemType Directory -Force -Path $wrapperBuildDir | Out-Null

& cl /c /O2 /nologo "/I$includeDir" "/I$wrapperDir" $nativeSource "/Fo$wrapperObj"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& link /nologo /dll "/OUT:$dllOut" "/IMPLIB:$implibOut" "/LIBPATH:$libDir" $wrapperObj $cryptoLib
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$binDir = Join-Path $Prefix "bin"
if (Test-Path -LiteralPath $binDir) {
  Get-ChildItem -Path $binDir -Filter "libcrypto-3*.dll" -ErrorAction SilentlyContinue | Copy-Item -Destination $wrapperDir -Force
  Get-ChildItem -Path $binDir -Filter "libssl-3*.dll" -ErrorAction SilentlyContinue | Copy-Item -Destination $wrapperDir -Force
}

$providerPath = Join-Path $Prefix "lib\ossl-modules"
Write-Host "SM2+ML-KEM wrapper built: $dllOut"
Write-Host "Provider path for tests: $providerPath"
Write-Host "Run: `$env:TONGSUO_PQ_PROVIDER_PATH='$providerPath'; go test -tags sm2mlkem ./crypto/sm2mlkem"
