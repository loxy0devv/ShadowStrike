# tools/bake_rules.ps1
# AUTO-RUN as a PreBuildEvent by PhantomCoreLib.vcxproj
#
# Reads every rule file from the four corpora, serialises them into the
# PHRB binary format, XOR-obfuscates the result, and writes a C++ source
# file that embeds the data as a static byte array.
#
# Usage (manual):
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\bake_rules.ps1 `
#       -SolutionDir "C:\...\ShadowStrike\" `
#       -OutFile     "C:\...\ShadowStrike\src\PhantomCore\Detection\Rules\RulesBlob.generated.cpp"

param(
    [string]$SolutionDir = (Split-Path -Parent $PSScriptRoot),
    [string]$OutFile     = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Sanitise $SolutionDir — MSBuild passes $(SolutionDir) with a trailing
# backslash, so the shell receives   -SolutionDir "D:\...\ShadowStrike\"
# where the \" is misinterpreted as an escaped quote, appending a literal
# '"' to the value.  Strip all trailing backslashes, quotes, and spaces,
# then add exactly one canonical trailing backslash back.
# ---------------------------------------------------------------------------
$SolutionDir = $SolutionDir.TrimEnd('"', '\', ' ', "`t")
if ($SolutionDir -eq '') {
    $SolutionDir = Split-Path -Parent $PSScriptRoot
}
$SolutionDir = $SolutionDir + '\'

# Default OutFile now that $SolutionDir is clean
if ($OutFile -eq '') {
    $OutFile = "${SolutionDir}src\PhantomCore\Detection\Rules\RulesBlob.generated.cpp"
}
# Sanitise OutFile the same way (in case it was also mangled)
$OutFile = $OutFile.TrimEnd('"', ' ', "`t")

# ---- XOR key (must match RulesBlobKey.hpp) --------------------------------
[byte[]]$key = @(
    0xA7, 0x3B, 0xF1, 0x0D, 0x5C, 0x82, 0x9E, 0x47,
    0x61, 0xCA, 0x2F, 0x73, 0xDE, 0x15, 0x88, 0xB4,
    0x39, 0x6D, 0xFC, 0xA1, 0x54, 0xE9, 0x07, 0xBB,
    0x2E, 0x90, 0x43, 0xC8, 0x71, 0x1A, 0xD6, 0x5F
)

# ---- Helper: write a little-endian uint16 ---------------------------------
function Write-U16LE([System.IO.BinaryWriter]$w, [uint16]$v) {
    $w.Write([byte]($v -band 0xFF))
    $w.Write([byte](($v -shr 8) -band 0xFF))
}

# ---- Helper: write a little-endian uint32 ---------------------------------
function Write-U32LE([System.IO.BinaryWriter]$w, [uint32]$v) {
    $w.Write([byte]($v -band 0xFF))
    $w.Write([byte](($v -shr 8) -band 0xFF))
    $w.Write([byte](($v -shr 16) -band 0xFF))
    $w.Write([byte](($v -shr 24) -band 0xFF))
}

# ---- Collect rule entries -------------------------------------------------
# Each entry: [srcType byte, filename string, content bytes]
$entries = [System.Collections.Generic.List[object]]::new()

# Helper: add an entry if the file exists and is non-empty
function Add-Entry([byte]$srcType, [string]$filePath) {
    if (-not (Test-Path $filePath -PathType Leaf)) { return }
    [byte[]]$raw = [System.IO.File]::ReadAllBytes($filePath)
    if ($raw.Length -eq 0) { return }
    $filename = [System.IO.Path]::GetFileName($filePath)
    $entries.Add([PSCustomObject]@{
        SrcType  = $srcType
        Filename = $filename
        Content  = $raw
    })
}

# ---- 0: Native rules — prefer new category layout (rules\native\), fall back to legacy (rules\phantom\)
$nativeNew    = Join-Path $SolutionDir 'rules\native'
$nativeLegacy = Join-Path $SolutionDir 'rules\phantom'
$nativeDir    = if (Test-Path $nativeNew -PathType Container) { $nativeNew } else { $nativeLegacy }
if (Test-Path $nativeDir -PathType Container) {
    Get-ChildItem -Path $nativeDir -Recurse -File -Include '*.yaml','*.yml','*.json' |
    ForEach-Object { Add-Entry 0 $_.FullName }
}

# ---- 1: capa rules — prefer external/ layout, fall back to legacy
$capaNew    = Join-Path $SolutionDir 'rules\external\capa\capa-rules-9.4.0'
$capaLegacy = Join-Path $SolutionDir 'rules\capa\capa-rules-9.4.0'
$capaDir    = if (Test-Path $capaNew -PathType Container) { $capaNew } else { $capaLegacy }
if (Test-Path $capaDir -PathType Container) {
    $skipStems = @('README','release','sync','tests','workflow')
    Get-ChildItem -Path $capaDir -Recurse -File -Include '*.yaml','*.yml' |
    Where-Object {
        ($skipStems -notcontains $_.BaseName) -and
        ([System.IO.File]::ReadAllText($_.FullName) -match '(?m)^rule:')
    } |
    ForEach-Object { Add-Entry 1 $_.FullName }
}

# ---- 2: Sigma rules — prefer external/ layout, fall back to legacy; Windows-relevant only
$sigmaNew    = Join-Path $SolutionDir 'rules\external\sigma'
$sigmaLegacy = Join-Path $SolutionDir 'rules\sigma'
$sigmaDir    = if (Test-Path $sigmaNew -PathType Container) { $sigmaNew } else { $sigmaLegacy }
if (Test-Path $sigmaDir -PathType Container) {
    Get-ChildItem -Path $sigmaDir -Recurse -File -Include '*.yaml','*.yml' |
    Where-Object {
        $text = [System.IO.File]::ReadAllText($_.FullName)
        ($text -match '(?m)product:\s*windows') -or
        ($text -match 'category:\s*(process_creation|network_connection|image_load|file_event|registry_event|dns_query|pipe_created|driver_loaded)')
    } |
    ForEach-Object { Add-Entry 2 $_.FullName }
}

# ---- 3: Elastic rules — prefer external/ layout, fall back to legacy
$elasticNew    = Join-Path $SolutionDir 'rules\external\elastic\custom-consolidated-rules.ndjson'
$elasticLegacy = Join-Path $SolutionDir 'rules\elastic\custom-consolidated-rules.ndjson'
$elasticFile   = if (Test-Path $elasticNew -PathType Leaf) { $elasticNew } else { $elasticLegacy }
if (Test-Path $elasticFile -PathType Leaf) {
    Add-Entry 3 $elasticFile
}

Write-Host "bake_rules.ps1: collected $($entries.Count) rule entries from '$SolutionDir'" -ForegroundColor Cyan

# ---- Serialise into PHRB binary format ------------------------------------
$ms  = [System.IO.MemoryStream]::new()
$bw  = [System.IO.BinaryWriter]::new($ms, [System.Text.Encoding]::UTF8, $true)

# Filter out entries whose filename is too long BEFORE writing the header
$validEntries = $entries | Where-Object {
    [System.Text.Encoding]::UTF8.GetByteCount($_.Filename) -le 65535
}
$skipped = $entries.Count - $validEntries.Count
if ($skipped -gt 0) {
    Write-Warning "bake_rules.ps1: skipping $skipped entries with oversized filenames"
}

# Header: magic 'PHRB', version 0x0001, entry_count
$bw.Write([byte]0x50)  # 'P'
$bw.Write([byte]0x48)  # 'H'
$bw.Write([byte]0x52)  # 'R'
$bw.Write([byte]0x42)  # 'B'
$bw.Write([byte]0x01)  # version lo
$bw.Write([byte]0x00)  # version hi

# Write header with ACTUAL entry count
Write-U32LE $bw ([uint32]$validEntries.Count)

# Loop over filtered entries (no more 'continue' needed for the filename check)
foreach ($e in $validEntries) {
    [byte[]]$fnBytes = [System.Text.Encoding]::UTF8.GetBytes($e.Filename)
    $bw.Write([byte]$e.SrcType)
    Write-U16LE $bw ([uint16]$fnBytes.Length)
    if ($fnBytes.Length -gt 0) { $bw.Write($fnBytes, 0, $fnBytes.Length) }
    Write-U32LE $bw ([uint32]$e.Content.Length)
    $bw.Write($e.Content, 0, $e.Content.Length)
}

$bw.Flush()
$bw.Dispose()
[byte[]]$plain = $ms.ToArray()
$ms.Dispose()

Write-Host "bake_rules.ps1: serialised $($plain.Length) bytes before XOR" -ForegroundColor Cyan

# ---- XOR obfuscation -------------------------------------------------------
[byte[]]$obfuscated = [byte[]]::new($plain.Length)
for ($i = 0; $i -lt $plain.Length; $i++) {
    $obfuscated[$i] = $plain[$i] -bxor $key[$i % 32]
}

# ---- Render C++ source file ------------------------------------------------
$sb = [System.Text.StringBuilder]::new($obfuscated.Length * 7)

[void]$sb.AppendLine('// AUTO-GENERATED by tools/bake_rules.ps1 — DO NOT EDIT')
[void]$sb.AppendLine('// Contains obfuscated compiled rule data for ShadowStrike Phantom EDR.')
[void]$sb.AppendLine('#include "pch.h"')
[void]$sb.AppendLine('#include "EmbeddedRuleLoader.hpp"')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('namespace ShadowStrike::Detection {')
[void]$sb.AppendLine('')

if ($obfuscated.Length -eq 0) {
    # Empty blob — dev build without baked rules
    [void]$sb.AppendLine('alignas(8) static const unsigned char kPhantomRulesDataRaw[] = { 0x00 };')
    [void]$sb.AppendLine('extern const unsigned char* kPhantomRulesData = nullptr;  // empty blob')
    [void]$sb.AppendLine('extern const size_t kPhantomRulesDataSize = 0;')
} else {
    [void]$sb.AppendLine('alignas(8) static const unsigned char kPhantomRulesDataRaw[] = {')

    $lineCount = 0
    $col       = 0
    [void]$sb.Append('    ')
    for ($i = 0; $i -lt $obfuscated.Length; $i++) {
        [void]$sb.Append(('0x{0:X2}' -f $obfuscated[$i]))
        if ($i -lt $obfuscated.Length - 1) {
            [void]$sb.Append(', ')
            $col++
            if ($col -eq 16) {
                [void]$sb.AppendLine()
                [void]$sb.Append('    ')
                $col = 0
            }
        }
    }
    [void]$sb.AppendLine()
    [void]$sb.AppendLine('};')
    [void]$sb.AppendLine('extern const unsigned char* kPhantomRulesData = kPhantomRulesDataRaw;')
    [void]$sb.AppendLine('extern const size_t kPhantomRulesDataSize = sizeof(kPhantomRulesDataRaw);')
}

[void]$sb.AppendLine('')
[void]$sb.AppendLine('} // namespace ShadowStrike::Detection')

# ---- Write output file (only if content changed — keeps MSBuild happy) ----
$newContent = $sb.ToString()
$outDir = Split-Path $OutFile -Parent
if (-not (Test-Path $outDir -PathType Container)) {
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
}

$write = $true
if (Test-Path $OutFile -PathType Leaf) {
    $existing = [System.IO.File]::ReadAllText($OutFile)
    if ($existing -eq $newContent) {
        $write = $false
        Write-Host "bake_rules.ps1: output unchanged, skipping write." -ForegroundColor DarkGray
    }
}

if ($write) {
    [System.IO.File]::WriteAllText($OutFile, $newContent, [System.Text.Encoding]::UTF8)
    Write-Host "bake_rules.ps1: wrote '$OutFile' ($($obfuscated.Length) obfuscated bytes, $($validEntries.Count) rules)" -ForegroundColor Green
}
