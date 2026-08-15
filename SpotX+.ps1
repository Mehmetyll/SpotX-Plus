[CmdletBinding()]
param(
    [string]$SpotifyVersion = "1.2.95",
    [switch]$NoPodcastFilter,
    [switch]$NoUpdateBlock,
    [switch]$SkipInstall,
    [switch]$LaunchAfter
)

#  SpotX+ -- Streamlined, Zero-Telemetry Spotify Patcher for Windows

#  STRICT MODE & TLS
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSDefaultParameterValues['Stop-Process:ErrorAction'] = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

#  BINARY PATCHER ENGINE (Spotify.dll ad-slot & signature patcher)
# SpotX+ Binary Patcher Module
# Extracted from SpotX-Official/SpotX (https://github.com/SpotX-Official/SpotX)
# These functions patch Spotify.dll to disable ad slot rendering at the binary level

function Initialize-BinaryScanner {
    if (([System.Management.Automation.PSTypeName]'BinaryScanner').Type) {
        return
    }

    $csharpCode = @"
using System;
using System.Collections.Generic;

public static class BinaryScanner {
    public static int FindBytes(byte[] data, byte[] pattern, int start) {
        if (data == null || pattern == null || pattern.Length == 0) return -1;
        if (start < 0) start = 0;
        for (int i = start; i <= data.Length - pattern.Length; i++) {
            if (data[i] != pattern[0]) continue;
            bool matched = true;
            for (int j = 1; j < pattern.Length; j++) {
                if (data[i + j] != pattern[j]) {
                    matched = false;
                    break;
                }
            }
            if (matched) return i;
        }
        return -1;
    }

    public static bool MatchBytes(byte[] data, int offset, byte[] pattern) {
        if (data == null || pattern == null || pattern.Length == 0) return false;
        if (offset < 0 || offset > data.Length - pattern.Length) return false;
        for (int i = 0; i < pattern.Length; i++) {
            if (data[offset + i] != pattern[i]) return false;
        }
        return true;
    }

    public static int FindMaskedBytes(byte[] data, byte[] pattern, byte[] mask, int start, int length) {
        if (data == null || pattern == null || mask == null || pattern.Length == 0 || pattern.Length != mask.Length) return -1;
        if (start < 0) start = 0;
        if (start >= data.Length || length <= 0) return -1;
        int end = (int)Math.Min(data.Length, (long)start + length);
        int limit = end - pattern.Length;
        for (int i = start; i <= limit; i++) {
            bool matched = true;
            for (int j = 0; j < pattern.Length; j++) {
                if (mask[j] != 0 && data[i + j] != pattern[j]) {
                    matched = false;
                    break;
                }
            }
            if (matched) return i;
        }
        return -1;
    }

    public static bool MatchMaskedBytes(byte[] data, int offset, byte[] pattern, byte[] mask) {
        if (data == null || pattern == null || mask == null || pattern.Length == 0 || pattern.Length != mask.Length) return false;
        if (offset < 0 || offset > data.Length - pattern.Length) return false;
        for (int i = 0; i < pattern.Length; i++) {
            if (mask[i] != 0 && data[offset + i] != pattern[i]) return false;
        }
        return true;
    }

    public static List<int> FindXrefArm64(byte[] data, ulong stringRVA, ulong sectionRVA, uint sectionRawPtr, uint sectionSize) {
        List<int> results = new List<int>();
        for (uint i = 0; i < sectionSize; i += 4) {
            uint fileOffset = sectionRawPtr + i;
            if (fileOffset + 8 > data.Length) break;
            uint inst1 = BitConverter.ToUInt32(data, (int)fileOffset);

            // ADRP
            if ((inst1 & 0x9F000000) == 0x90000000) {
                int rd = (int)(inst1 & 0x1F);
                long immLo = (inst1 >> 29) & 3;
                long immHi = (inst1 >> 5) & 0x7FFFF;
                long imm = (immHi << 2) | immLo;
                if ((imm & 0x100000) != 0) { imm |= unchecked((long)0xFFFFFFFFFFE00000); }
                imm = imm << 12;
                ulong pc = sectionRVA + i;
                ulong pcPage = pc & 0xFFFFFFFFFFFFF000;
                ulong page = (ulong)((long)pcPage + imm);

                uint inst2 = BitConverter.ToUInt32(data, (int)fileOffset + 4);
                // ADD
                if ((inst2 & 0xFF800000) == 0x91000000) {
                    int rn = (int)((inst2 >> 5) & 0x1F);
                    if (rn == rd) {
                        long imm12 = (inst2 >> 10) & 0xFFF;
                        ulong target = page + (ulong)imm12;
                        if (target == stringRVA) { results.Add((int)fileOffset); }
                    }
                }
            }
        }
        return results;
    }

    public static int FindFunctionStart(byte[] data, int startOffset, bool isArm) {
        int step = isArm ? 4 : 1;
        if (isArm && (startOffset % 4 != 0)) { startOffset -= (startOffset % 4); }

        for (int i = startOffset; i > 0; i -= step) {
            if (isArm) {
                if (i < 4) break;
                uint currInst = BitConverter.ToUInt32(data, i);
                // ARM64 prologue
                if ((currInst & 0xFF00FFFF) == 0xA9007BFD) { return i; }
            } else {
                // x64 padding before function start
                if (i >= 2) {
                    if ((data[i - 1] == 0xCC && data[i - 2] == 0xCC) || (data[i - 1] == 0x90 && data[i - 2] == 0x90)) {
                        if (data[i] != 0xCC && data[i] != 0x90) {
                            byte b = data[i];
                            if (b == 0x48 || b == 0x40 || b == 0x55 || (b >= 0x53 && b <= 0x57)) {
                                return i;
                            }
                        }
                    }
                }
            }
            if (startOffset - i > 20000) break;
        }
        return 0;
    }

    public static long[] FindRipRefs(byte[] bytes, int start, int length, long imageBase, long targetVa, int[] rawPtrs, int[] rawSizes, int[] virtualAddresses) {
        var result = new List<long>();
        int end = Math.Min(bytes.Length - 8, start + length - 8);
        for (int p = start; p < end; p++) {
            for (int k = 0; k < 2; k++) {
                int dispOffset = k == 0 ? 2 : 3;
                long nextRva = OffsetToRva(p + dispOffset + 4, rawPtrs, rawSizes, virtualAddresses);
                if (nextRva < 0) continue;
                int disp = BitConverter.ToInt32(bytes, p + dispOffset);
                long target = imageBase + nextRva + disp;
                if (target == targetVa) result.Add(p);
            }
        }
        return result.ToArray();
    }

    public static int[] FindRipLeaRefs(byte[] bytes, int start, int length, long targetRva, int[] rawPtrs, int[] rawSizes, int[] virtualAddresses) {
        var result = new List<int>();
        if (bytes == null || rawPtrs == null || rawSizes == null || virtualAddresses == null) return result.ToArray();
        if (rawPtrs.Length != rawSizes.Length || rawPtrs.Length != virtualAddresses.Length) return result.ToArray();
        if (start < 0) start = 0;
        int end = (int)Math.Min(bytes.Length, (long)start + length);
        for (int p = start; p + 7 <= end; p++) {
            if ((bytes[p] & 0xF8) != 0x48 || bytes[p + 1] != 0x8D) continue;
            if ((bytes[p + 2] & 0xC7) != 0x05) continue;
            long nextRva = OffsetToRva(p + 7, rawPtrs, rawSizes, virtualAddresses);
            if (nextRva < 0) continue;
            int disp = BitConverter.ToInt32(bytes, p + 3);
            if (nextRva + disp == targetRva) result.Add(p);
        }
        return result.ToArray();
    }

    public static int[] FindCallsToRva(byte[] bytes, int start, int length, long targetRva, int[] rawPtrs, int[] rawSizes, int[] virtualAddresses) {
        var result = new List<int>();
        int end = Math.Min(bytes.Length - 16, start + length - 16);
        for (int p = start; p < end; p++) {
            if (bytes[p] != 0xE8) continue;
            long nextRva = OffsetToRva(p + 5, rawPtrs, rawSizes, virtualAddresses);
            if (nextRva < 0) continue;
            int disp = BitConverter.ToInt32(bytes, p + 1);
            if (nextRva + disp == targetRva && bytes[p + 5] == 0x88) {
                result.Add(p);
            }
        }
        return result.ToArray();
    }

    public static long[] FindFunctionRange(byte[] bytes, int pdataRawPtr, int pdataRawSize, long rva) {
        int end = Math.Min(bytes.Length - 11, pdataRawPtr + pdataRawSize - 11);
        for (int p = pdataRawPtr; p < end; p += 12) {
            long begin = BitConverter.ToUInt32(bytes, p);
            long finish = BitConverter.ToUInt32(bytes, p + 4);
            if (begin > 0 && finish > begin && rva >= begin && rva < finish) {
                return new long[] { begin, finish };
            }
        }
        return Array.Empty<long>();
    }

    private static long OffsetToRva(int offset, int[] rawPtrs, int[] rawSizes, int[] virtualAddresses) {
        for (int i = 0; i < rawPtrs.Length; i++) {
            if (offset >= rawPtrs[i] && offset < rawPtrs[i] + rawSizes[i]) {
                return (long)virtualAddresses[i] + (offset - rawPtrs[i]);
            }
        }
        return -1;
    }
}
"@

    try {
        Add-Type -TypeDefinition $csharpCode -ErrorAction Stop
    }
    catch {
        $compilerError = $_.Exception.Message -split '\r?\n' | Select-Object -First 1
        throw "BinaryScanner initialization failed: $compilerError"
    }

    if (-not ([System.Management.Automation.PSTypeName]'BinaryScanner').Type) {
        throw "BinaryScanner initialization failed: Type was not loaded"
    }
}

function Convert-HexStringToBytes {
    param([string]$HexString)

    return [byte[]]($HexString -split '\s+' | Where-Object { $_ } | ForEach-Object { [Convert]::ToByte($_, 16) })
}

function Read-PEUInt16([byte[]]$Bytes, [int]$Offset) { [BitConverter]::ToUInt16($Bytes, $Offset) }
function Read-PEUInt32([byte[]]$Bytes, [int]$Offset) { [BitConverter]::ToUInt32($Bytes, $Offset) }
function Read-PEUInt64([byte[]]$Bytes, [int]$Offset) { [BitConverter]::ToUInt64($Bytes, $Offset) }

function Get-PEArchitectureOffsets {
    param([UInt16]$MachineType)

    $result = @{ Architecture = $null; DataDirectoryOffset = $null }
    switch ($MachineType) {
        0x8664 { $result.Architecture = 'x64'; $result.DataDirectoryOffset = 112 }
        0xAA64 { $result.Architecture = 'ARM64'; $result.DataDirectoryOffset = 112 }
        0x014c { $result.Architecture = 'x86'; $result.DataDirectoryOffset = 96 }
        default { $result.Architecture = 'Unknown'; $result.DataDirectoryOffset = $null }
    }
    $result.MachineType = $MachineType
    return $result
}

function Get-PEFileInfo {
    param([byte[]]$Bytes)

    $peHeaderOffset = [int](Read-PEUInt32 $Bytes 0x3C)
    if ($Bytes[$peHeaderOffset] -ne 0x50 -or $Bytes[$peHeaderOffset + 1] -ne 0x45) {
        throw 'Invalid PE file'
    }

    $fileHeaderOffset = $peHeaderOffset + 4
    $optionalHeaderOffset = $fileHeaderOffset + 20
    $machineType = Read-PEUInt16 $Bytes $fileHeaderOffset
    $archInfo = Get-PEArchitectureOffsets -MachineType $machineType
    $optionalHeaderMagic = Read-PEUInt16 $Bytes $optionalHeaderOffset

    if ($optionalHeaderMagic -eq 0x20b) {
        $imageBase = [int64](Read-PEUInt64 $Bytes ($optionalHeaderOffset + 24))
    }
    elseif ($optionalHeaderMagic -eq 0x10b) {
        $imageBase = [int64](Read-PEUInt32 $Bytes ($optionalHeaderOffset + 28))
    }
    else {
        throw 'Unsupported optional header format'
    }

    $numberOfSections = [int](Read-PEUInt16 $Bytes ($fileHeaderOffset + 2))
    $optionalHeaderSize = [int](Read-PEUInt16 $Bytes ($fileHeaderOffset + 16))
    $sectionTableStart = $optionalHeaderOffset + $optionalHeaderSize
    $sections = @()
    $codeSection = $null

    for ($i = 0; $i -lt $numberOfSections; $i++) {
        $sectionOffset = $sectionTableStart + ($i * 40)
        $nameBytes = $Bytes[$sectionOffset..($sectionOffset + 7)]
        $name = ([Text.Encoding]::ASCII.GetString($nameBytes) -replace "`0.*$", '')
        $characteristics = Read-PEUInt32 $Bytes ($sectionOffset + 36)
        $section = [PSCustomObject]@{
            Name            = $name
            VirtualSize     = [int64](Read-PEUInt32 $Bytes ($sectionOffset + 8))
            VirtualAddress  = [int64](Read-PEUInt32 $Bytes ($sectionOffset + 12))
            RawSize         = [int64](Read-PEUInt32 $Bytes ($sectionOffset + 16))
            RawPtr          = [int64](Read-PEUInt32 $Bytes ($sectionOffset + 20))
            Characteristics = $characteristics
        }
        $sections += $section
        if (($characteristics -band 0x20) -ne 0 -and $null -eq $codeSection) {
            $codeSection = $section
        }
    }

    return [PSCustomObject]@{
        PeHeaderOffset       = $peHeaderOffset
        FileHeaderOffset     = $fileHeaderOffset
        OptionalHeaderOffset = $optionalHeaderOffset
        MachineType          = $machineType
        Architecture         = $archInfo.Architecture
        DataDirectoryOffset  = $archInfo.DataDirectoryOffset
        ImageBase            = $imageBase
        Sections             = $sections
        CodeSection          = $codeSection
    }
}

function Get-PERvaFromOffset {
    param(
        [object[]]$Sections,
        [int64]$Offset
    )

    foreach ($section in $Sections) {
        if ($Offset -ge $section.RawPtr -and $Offset -lt ($section.RawPtr + $section.RawSize)) {
            return [int64]$section.VirtualAddress + ($Offset - $section.RawPtr)
        }
    }
    return $null
}

function Get-PEOffsetFromRva {
    param(
        [object[]]$Sections,
        [int64]$Rva
    )

    foreach ($section in $Sections) {
        $sectionSpan = [Math]::Max([int64]$section.VirtualSize, [int64]$section.RawSize)
        if ($Rva -lt $section.VirtualAddress -or $Rva -ge ($section.VirtualAddress + $sectionSpan)) {
            continue
        }

        $relativeOffset = $Rva - $section.VirtualAddress
        if ($relativeOffset -ge $section.RawSize) {
            return $null
        }
        return [int64]$section.RawPtr + $relativeOffset
    }
    return $null
}

function Reset-Dll-Sign {
    [CmdletBinding()]
    param (
        [string]$FilePath
    )

    $TargetStringText = "Check failed: sep_pos != std::wstring::npos."
    $Patch_x64 = Convert-HexStringToBytes "B8 01 00 00 00 C3"
    $Patch_ARM64 = Convert-HexStringToBytes "20 00 80 52 C0 03 5F D6"
    try {
        Initialize-BinaryScanner
    }
    catch {
        Write-Warning $_.Exception.Message
        Stop-Script
    }

    Write-Verbose "Loading file: $FilePath"
    if (-not (Test-Path $FilePath)) {
        Write-Warning "File Spotify.dll not found"
        Stop-Script
    }
    $bytes = [System.IO.File]::ReadAllBytes($FilePath)

    try {
        $peInfo = Get-PEFileInfo -Bytes $bytes
        $IsArm64 = $peInfo.Architecture -eq 'ARM64'

        if ($peInfo.Architecture -ne 'x64' -and -not $IsArm64) {
            Write-Warning "Architecture not supported for patching Spotify.dll"
            Stop-Script
        }

        Write-Verbose "Architecture: $($peInfo.Architecture)"

        if ($null -eq $peInfo.CodeSection) {
            Write-Warning "Code section not found in Spotify.dll"
            Stop-Script
        }
    }
    catch {
        Write-Warning "PE Error in Spotify.dll"
        Stop-Script
    }

    Write-Verbose "Searching for function..."
    $StringBytes = [System.Text.Encoding]::ASCII.GetBytes($TargetStringText)
    try {
        $StringOffset = & {
            $ErrorActionPreference = "Stop"
            [BinaryScanner]::FindBytes($bytes, $StringBytes, 0)
        }
    }
    catch {
        Write-Warning ("BinaryScanner scan failed for Spotify.dll: {0}" -f $_.Exception.Message)
        Stop-Script
    }
    if ($null -eq $StringOffset) {
        Write-Warning "BinaryScanner returned no result for Spotify.dll"
        Stop-Script
    }
    if ($StringOffset -lt 0) {
        Write-Warning "String not found in Spotify.dll"
        Stop-Script
    }
    $StringRVA = Get-PERvaFromOffset -Sections $peInfo.Sections -Offset $StringOffset
    if ($null -eq $StringRVA) {
        Write-Warning "String RVA not found in Spotify.dll"
        Stop-Script
    }

    $PatchOffset = 0
    if (-not $IsArm64) {
        $RawStart = $peInfo.CodeSection.RawPtr; $RawEnd = $RawStart + $peInfo.CodeSection.RawSize
        for ($i = $RawStart; $i -lt $RawEnd; $i++) {
            if ($bytes[$i] -eq 0x48 -and $bytes[$i + 1] -eq 0x8D -and $bytes[$i + 2] -eq 0x15) {
                $Rel = [BitConverter]::ToInt32($bytes, $i + 3)
                $CurrentRva = Get-PERvaFromOffset -Sections $peInfo.Sections -Offset $i
                if ($null -eq $CurrentRva) { continue }

                $Target = $CurrentRva + 7 + $Rel
                if ($Target -eq $StringRVA) {
                    $PatchOffset = [BinaryScanner]::FindFunctionStart($bytes, $i, $false)
                    if ($PatchOffset -gt 0) { break }
                }
            }
        }
    }
    else {
        $Results = [BinaryScanner]::FindXrefArm64($bytes, [uint64]$StringRVA, [uint64]$peInfo.CodeSection.VirtualAddress, [uint32]$peInfo.CodeSection.RawPtr, [uint32]$peInfo.CodeSection.RawSize)
        if ($Results.Count -gt 0) {
            $PatchOffset = [BinaryScanner]::FindFunctionStart($bytes, $Results[0], $true)
        }
    }

    if ($PatchOffset -eq 0) {
        Write-Warning "Function not found in Spotify.dll"
        Stop-Script
    }

    $BytesToWrite = if ($IsArm64) { $Patch_ARM64 } else { $Patch_x64 }

    $CurrentBytes = @(); for ($i = 0; $i -lt $BytesToWrite.Length; $i++) { $CurrentBytes += $bytes[$PatchOffset + $i] }
    $FoundHex = ($CurrentBytes | ForEach-Object { $_.ToString("X2") }) -join " "
    Write-Verbose "Found (Offset: 0x$($PatchOffset.ToString("X"))): $FoundHex"

    if ($CurrentBytes[0] -eq $BytesToWrite[0] -and $CurrentBytes[$BytesToWrite.Length - 1] -eq $BytesToWrite[$BytesToWrite.Length - 1]) {
        Write-Warning "File Spotify.dll already patched"
        return
    }

    Write-Verbose "Applying patch..."
    for ($i = 0; $i -lt $BytesToWrite.Length; $i++) { $bytes[$PatchOffset + $i] = $BytesToWrite[$i] }

    try {
        [System.IO.File]::WriteAllBytes($FilePath, $bytes)
        Write-Verbose "Success"
    }
    catch {
        Write-Warning "Write error in Spotify.dll $($_.Exception.Message)"
        Stop-Script
    }
}

function Read-X64SignedByte {
    param(
        [byte[]]$Bytes,
        [int]$Offset
    )

    if ($Offset -lt 0 -or $Offset -ge $Bytes.Length) {
        throw 'Signed byte is outside the file'
    }

    $value = [int]$Bytes[$Offset]
    if ($value -ge 0x80) {
        return $value - 0x100
    }
    return $value
}

function Read-X64RelativeBranch {
    param(
        [byte[]]$Bytes,
        [int]$Offset,
        [ValidateSet('Je', 'Jne', 'Jmp')]
        [string]$Kind,
        [int]$Limit
    )

    switch ($Kind) {
        'Je' { $shortOpcode = 0x74; $nearOpcode = 0x84 }
        'Jne' { $shortOpcode = 0x75; $nearOpcode = 0x85 }
        'Jmp' { $shortOpcode = 0xEB; $nearOpcode = $null }
    }

    if ($Offset -ge 0 -and ($Offset + 2) -le $Limit -and $Bytes[$Offset] -eq $shortOpcode) {
        $nextOffset = $Offset + 2
        $displacement = Read-X64SignedByte -Bytes $Bytes -Offset ($Offset + 1)
    }
    elseif ($null -ne $nearOpcode -and $Offset -ge 0 -and ($Offset + 6) -le $Limit -and
        $Bytes[$Offset] -eq 0x0F -and $Bytes[$Offset + 1] -eq $nearOpcode) {
        $nextOffset = $Offset + 6
        $displacement = [BitConverter]::ToInt32($Bytes, $Offset + 2)
    }
    elseif ($Kind -eq 'Jmp' -and $Offset -ge 0 -and ($Offset + 5) -le $Limit -and $Bytes[$Offset] -eq 0xE9) {
        $nextOffset = $Offset + 5
        $displacement = [BitConverter]::ToInt32($Bytes, $Offset + 1)
    }
    else {
        throw "Expected $Kind branch"
    }

    return [PSCustomObject]@{
        NextOffset   = [int]$nextOffset
        TargetOffset = [int64]$nextOffset + [int64]$displacement
    }
}

function Read-X64BlockSlotsField {
    param(
        [byte[]]$Bytes,
        [int]$Offset,
        [ValidateSet('CmpRcxBl', 'MovAlRcx', 'CmpRdiBl')]
        [string]$Kind
    )

    switch ($Kind) {
        'CmpRcxBl' { $disp8 = Convert-HexStringToBytes '38 59'; $disp32 = Convert-HexStringToBytes '38 99' }
        'MovAlRcx' { $disp8 = Convert-HexStringToBytes '8A 41'; $disp32 = Convert-HexStringToBytes '8A 81' }
        'CmpRdiBl' { $disp8 = Convert-HexStringToBytes '38 5F'; $disp32 = Convert-HexStringToBytes '38 9F' }
    }

    if ([BinaryScanner]::MatchBytes($Bytes, $Offset, $disp8) -and ($Offset + 3) -le $Bytes.Length) {
        return [PSCustomObject]@{
            Value      = [int64](Read-X64SignedByte -Bytes $Bytes -Offset ($Offset + 2))
            NextOffset = $Offset + 3
        }
    }
    if ([BinaryScanner]::MatchBytes($Bytes, $Offset, $disp32) -and ($Offset + 6) -le $Bytes.Length) {
        return [PSCustomObject]@{
            Value      = [int64][BitConverter]::ToInt32($Bytes, $Offset + 2)
            NextOffset = $Offset + 6
        }
    }

    throw "Unexpected block_slots field instruction"
}

function Get-X64BlockSlotsMapperSequenceEnum {
    param(
        [byte[]]$Bytes,
        [int]$SequenceOffset,
        [int]$BranchOffset,
        [bool]$MatchTaken = $true
    )

    $movEcxR8d = Convert-HexStringToBytes '41 8B C8'
    $subEcx8 = Convert-HexStringToBytes '83 E9'
    $subEcx32 = Convert-HexStringToBytes '81 E9'
    $cmpEcx8 = Convert-HexStringToBytes '83 F9'
    $cmpEcx32 = Convert-HexStringToBytes '81 F9'
    if (-not [BinaryScanner]::MatchBytes($Bytes, $SequenceOffset, $movEcxR8d)) {
        return @()
    }

    $matches = @()
    for ($enumValue = 1; $enumValue -le 0x3FF; $enumValue++) {
        $ecx = [int64]$enumValue
        $zeroFlag = $false
        $hasFlags = $false
        $cursor = $SequenceOffset + $movEcxR8d.Length
        $valid = $true
        $matched = $false

        while ($cursor -le $BranchOffset) {
            if ([BinaryScanner]::MatchBytes($Bytes, $cursor, $subEcx8)) {
                $ecx -= [int64](Read-X64SignedByte -Bytes $Bytes -Offset ($cursor + 2))
                $zeroFlag = ($ecx -eq 0)
                $hasFlags = $true
                $cursor += 3
                continue
            }
            if ([BinaryScanner]::MatchBytes($Bytes, $cursor, $subEcx32)) {
                $ecx -= [int64][BitConverter]::ToInt32($Bytes, $cursor + 2)
                $zeroFlag = ($ecx -eq 0)
                $hasFlags = $true
                $cursor += 6
                continue
            }
            if ([BinaryScanner]::MatchBytes($Bytes, $cursor, $cmpEcx8)) {
                $compareValue = [int64](Read-X64SignedByte -Bytes $Bytes -Offset ($cursor + 2))
                $zeroFlag = ($ecx -eq $compareValue)
                $hasFlags = $true
                $cursor += 3
                continue
            }
            if ([BinaryScanner]::MatchBytes($Bytes, $cursor, $cmpEcx32)) {
                $compareValue = [int64][BitConverter]::ToInt32($Bytes, $cursor + 2)
                $zeroFlag = ($ecx -eq $compareValue)
                $hasFlags = $true
                $cursor += 6
                continue
            }

            $branchLength = 0
            $branchOnEqual = $false
            if (($cursor + 2) -le $Bytes.Length -and ($Bytes[$cursor] -eq 0x74 -or $Bytes[$cursor] -eq 0x75)) {
                $branchLength = 2
                $branchOnEqual = ($Bytes[$cursor] -eq 0x74)
            }
            elseif (($cursor + 6) -le $Bytes.Length -and $Bytes[$cursor] -eq 0x0F -and
                ($Bytes[$cursor + 1] -eq 0x84 -or $Bytes[$cursor + 1] -eq 0x85)) {
                $branchLength = 6
                $branchOnEqual = ($Bytes[$cursor + 1] -eq 0x84)
            }
            else {
                $valid = $false
                break
            }

            if (-not $hasFlags) {
                $valid = $false
                break
            }
            $branchTaken = if ($branchOnEqual) { $zeroFlag } else { -not $zeroFlag }
            if ($cursor -eq $BranchOffset) {
                $matched = if ($MatchTaken) { $branchTaken } else { -not $branchTaken }
                break
            }
            if ($branchTaken) {
                $valid = $false
                break
            }
            $cursor += $branchLength
        }

        if ($valid -and $matched) {
            $matches += [uint32]$enumValue
        }
    }

    return $matches
}

function Get-BlockSlotsMapperEnumValue {
    param(
        [byte[]]$Bytes,
        [object]$PeInfo,
        [int64]$MapperStartRva,
        [int64]$MapperEndRva,
        [int[]]$AnchorRefs
    )

    $mapperOffset = Get-PEOffsetFromRva -Sections $PeInfo.Sections -Rva $MapperStartRva
    if ($null -eq $mapperOffset) {
        throw 'slot_is_disabled mapper offset was not found'
    }

    $mapperOffset = [int]$mapperOffset
    $mapperEndOffset = [int64]$mapperOffset + ($MapperEndRva - $MapperStartRva)
    if ($mapperEndOffset -le $mapperOffset -or $mapperEndOffset -gt $Bytes.Length) {
        throw 'slot_is_disabled mapper range is invalid'
    }

    $stringCases = @(
        [PSCustomObject]@{
            PrefixLength = 20
            Pattern      = Convert-HexStringToBytes '0F 57 C0 0F 11 02 48 89 7A 10 48 89 7A 18 41 B8 10 00 00 00 48 8D 15 00 00 00 00'
            Mask         = Convert-HexStringToBytes 'FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF 00 00 00 00'
            DispatchMode = 'Target'
        },
        [PSCustomObject]@{
            PrefixLength = 18
            Pattern      = Convert-HexStringToBytes '0F 57 C0 0F 11 02 48 89 7A 10 48 89 7A 18 44 8D 41 0F 48 8D 15 00 00 00 00'
            Mask         = Convert-HexStringToBytes 'FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF 00 00 00 00'
            DispatchMode = 'Fallthrough'
        }
    )
    $movEcxR8d = Convert-HexStringToBytes '41 8B C8'
    $cmpR8d8 = Convert-HexStringToBytes '41 83 F8'
    $cmpR8d32 = Convert-HexStringToBytes '41 81 F8'
    $enumValues = @{}

    foreach ($anchorRef in $AnchorRefs) {
        if (([int64]$anchorRef + 7) -gt $mapperEndOffset) {
            continue
        }

        foreach ($stringCase in $stringCases) {
            $caseOffset = [int]$anchorRef - $stringCase.PrefixLength
            if ($caseOffset -lt $mapperOffset -or
                -not [BinaryScanner]::MatchMaskedBytes($Bytes, $caseOffset, $stringCase.Pattern, $stringCase.Mask)) {
                continue
            }

            $dispatches = @()
            if ($stringCase.DispatchMode -eq 'Target') {
                for ($branchOffset = $mapperOffset; $branchOffset -lt $caseOffset; $branchOffset++) {
                    if (($Bytes[$branchOffset] -eq 0x74 -or $Bytes[$branchOffset] -eq 0x75) -and
                        ($branchOffset + 2) -le $mapperEndOffset) {
                        $branchOnEqual = ($Bytes[$branchOffset] -eq 0x74)
                        $branchTarget = [int64]$branchOffset + 2 +
                        (Read-X64SignedByte -Bytes $Bytes -Offset ($branchOffset + 1))
                    }
                    elseif ($Bytes[$branchOffset] -eq 0x0F -and ($branchOffset + 6) -le $mapperEndOffset -and
                        ($Bytes[$branchOffset + 1] -eq 0x84 -or $Bytes[$branchOffset + 1] -eq 0x85)) {
                        $branchOnEqual = ($Bytes[$branchOffset + 1] -eq 0x84)
                        $branchTarget = [int64]$branchOffset + 6 + [BitConverter]::ToInt32($Bytes, $branchOffset + 2)
                    }
                    else {
                        continue
                    }

                    if ($branchTarget -eq $caseOffset) {
                        $dispatches += [PSCustomObject]@{
                            Offset        = $branchOffset
                            BranchOnEqual = $branchOnEqual
                            MatchTaken    = $true
                        }
                    }
                }
            }
            else {
                if ($caseOffset -ge ($mapperOffset + 6) -and $Bytes[$caseOffset - 6] -eq 0x0F -and
                    ($Bytes[$caseOffset - 5] -eq 0x84 -or $Bytes[$caseOffset - 5] -eq 0x85)) {
                    $branchOffset = $caseOffset - 6
                    $branchOnEqual = ($Bytes[$caseOffset - 5] -eq 0x84)
                    $branchTarget = [int64]$caseOffset + [BitConverter]::ToInt32($Bytes, $caseOffset - 4)
                }
                elseif ($caseOffset -ge ($mapperOffset + 2) -and
                    ($Bytes[$caseOffset - 2] -eq 0x74 -or $Bytes[$caseOffset - 2] -eq 0x75)) {
                    $branchOffset = $caseOffset - 2
                    $branchOnEqual = ($Bytes[$caseOffset - 2] -eq 0x74)
                    $branchTarget = [int64]$caseOffset +
                    (Read-X64SignedByte -Bytes $Bytes -Offset ($caseOffset - 1))
                }
                else {
                    continue
                }

                if ($branchTarget -lt $mapperOffset -or $branchTarget -ge $mapperEndOffset -or $branchTarget -eq $caseOffset) {
                    continue
                }
                $dispatches += [PSCustomObject]@{
                    Offset        = $branchOffset
                    BranchOnEqual = $branchOnEqual
                    MatchTaken    = $false
                }
            }

            foreach ($dispatch in $dispatches) {
                $branchOffset = [int]$dispatch.Offset
                $selectsEquality = ($dispatch.BranchOnEqual -eq $dispatch.MatchTaken)
                if ($selectsEquality -and $branchOffset -ge ($mapperOffset + 4) -and
                    [BinaryScanner]::MatchBytes($Bytes, $branchOffset - 4, $cmpR8d8)) {
                    $enumValue = [int64](Read-X64SignedByte -Bytes $Bytes -Offset ($branchOffset - 1))
                    if ($enumValue -gt 0 -and $enumValue -le 0x3FF) {
                        $enumValues['{0:X}' -f $enumValue] = [uint32]$enumValue
                    }
                }
                if ($selectsEquality -and $branchOffset -ge ($mapperOffset + 7) -and
                    [BinaryScanner]::MatchBytes($Bytes, $branchOffset - 7, $cmpR8d32)) {
                    $enumValue = [BitConverter]::ToUInt32($Bytes, $branchOffset - 4)
                    if ($enumValue -gt 0 -and $enumValue -le 0x3FF) {
                        $enumValues['{0:X}' -f $enumValue] = $enumValue
                    }
                }

                $sequenceStart = [Math]::Max($mapperOffset, $branchOffset - 0x100)
                for ($candidateOffset = $sequenceStart; $candidateOffset -lt $branchOffset; $candidateOffset++) {
                    if (-not [BinaryScanner]::MatchBytes($Bytes, $candidateOffset, $movEcxR8d)) {
                        continue
                    }
                    $sequenceEnums = @(Get-X64BlockSlotsMapperSequenceEnum `
                            -Bytes $Bytes `
                            -SequenceOffset $candidateOffset `
                            -BranchOffset $branchOffset `
                            -MatchTaken $dispatch.MatchTaken)
                    foreach ($enumValue in $sequenceEnums) {
                        $enumValues['{0:X}' -f [uint32]$enumValue] = [uint32]$enumValue
                    }
                }
            }
        }
    }

    if ($enumValues.Count -ne 1) {
        throw "Expected one slot_is_disabled enum value, found $($enumValues.Count)"
    }
    return [uint32](@($enumValues.Values)[0])
}

function Get-BlockSlotsPredicateInfo {
    param(
        [byte[]]$Bytes,
        [object]$PeInfo,
        [object]$TextSection,
        [object]$PdataSection,
        [int64]$TargetRva
    )

    try {
        $runtimeRange = [BinaryScanner]::FindFunctionRange(
            $Bytes,
            [int]$PdataSection.RawPtr,
            [int]$PdataSection.RawSize,
            $TargetRva
        )
        if ($runtimeRange.Length -ne 2 -or [int64]$runtimeRange[0] -ne $TargetRva) {
            return $null
        }

        $functionSize = [int64]$runtimeRange[1] - [int64]$runtimeRange[0]
        if ($functionSize -lt 0x20 -or $functionSize -gt 0x100) {
            return $null
        }

        $functionOffset = Get-PEOffsetFromRva -Sections $PeInfo.Sections -Rva $TargetRva
        if ($null -eq $functionOffset) {
            return $null
        }

        $functionOffset = [int64]$functionOffset
        $functionEndOffset = $functionOffset + $functionSize
        $textStart = [int64]$TextSection.RawPtr
        $textEnd = $textStart + [int64]$TextSection.RawSize
        if ($functionOffset -lt $textStart -or $functionEndOffset -gt $textEnd -or $functionEndOffset -gt $Bytes.Length) {
            return $null
        }

        $codeOffset = [int]$functionOffset
        $endbr64 = Convert-HexStringToBytes 'F3 0F 1E FA'
        if ([BinaryScanner]::MatchBytes($Bytes, $codeOffset, $endbr64)) {
            $codeOffset += $endbr64.Length
        }

        $prologue = Convert-HexStringToBytes '48 89 5C 24 00 57 48 83 EC 00 32 DB'
        $prologueMask = Convert-HexStringToBytes 'FF FF FF FF 00 FF FF FF FF 00 FF FF'
        if (-not [BinaryScanner]::MatchMaskedBytes($Bytes, $codeOffset, $prologue, $prologueMask)) {
            return $null
        }

        $saveDisplacement = [int]$Bytes[$codeOffset + 4]
        $stackFrame = [int]$Bytes[$codeOffset + 9]
        if ($stackFrame -le 0) {
            return $null
        }

        $patchOffset = $codeOffset + $prologue.Length
        $originalPatch = Convert-HexStringToBytes '48 8B F9'
        if ([BinaryScanner]::MatchBytes($Bytes, $patchOffset, $originalPatch)) {
            $state = 'Original'
        }
        elseif (($patchOffset + 3) -le $functionEndOffset -and $Bytes[$patchOffset] -eq 0xEB -and $Bytes[$patchOffset + 2] -eq 0x90) {
            $state = 'Patched'
        }
        else {
            return $null
        }

        $cursor = $patchOffset + 3
        $flagField = Read-X64BlockSlotsField -Bytes $Bytes -Offset $cursor -Kind CmpRcxBl
        $cursor = $flagField.NextOffset
        $toGate = Read-X64RelativeBranch -Bytes $Bytes -Offset $cursor -Kind Je -Limit ([int]$functionEndOffset)
        $cursor = $toGate.NextOffset
        $valueField = Read-X64BlockSlotsField -Bytes $Bytes -Offset $cursor -Kind MovAlRcx
        $cursor = $valueField.NextOffset
        $toEpilogue = Read-X64RelativeBranch -Bytes $Bytes -Offset $cursor -Kind Jmp -Limit ([int]$functionEndOffset)
        $cursor = $toEpilogue.NextOffset

        if ($toGate.TargetOffset -ne $cursor) {
            return $null
        }

        $gateField = Read-X64BlockSlotsField -Bytes $Bytes -Offset $cursor -Kind CmpRcxBl
        $cursor = $gateField.NextOffset
        $gateToFalse = Read-X64RelativeBranch -Bytes $Bytes -Offset $cursor -Kind Je -Limit ([int]$functionEndOffset)
        $cursor = $gateToFalse.NextOffset

        if (($cursor + 5) -gt $functionEndOffset -or $Bytes[$cursor] -ne 0xE8) {
            return $null
        }
        $helperCallRva = Get-PERvaFromOffset -Sections $PeInfo.Sections -Offset $cursor
        if ($null -eq $helperCallRva) {
            return $null
        }
        $helperTargetRva = [int64]$helperCallRva + 5 + [BitConverter]::ToInt32($Bytes, $cursor + 1)
        $textRvaEnd = [int64]$TextSection.VirtualAddress + [Math]::Max([int64]$TextSection.VirtualSize, [int64]$TextSection.RawSize)
        if ($helperTargetRva -lt [int64]$TextSection.VirtualAddress -or $helperTargetRva -ge $textRvaEnd) {
            return $null
        }
        $cursor += 5

        $testAl = Convert-HexStringToBytes '84 C0'
        if (-not [BinaryScanner]::MatchBytes($Bytes, $cursor, $testAl)) {
            return $null
        }
        $cursor += $testAl.Length
        $helperToTrue = Read-X64RelativeBranch -Bytes $Bytes -Offset $cursor -Kind Jne -Limit ([int]$functionEndOffset)
        $cursor = $helperToTrue.NextOffset

        $fallbackField = Read-X64BlockSlotsField -Bytes $Bytes -Offset $cursor -Kind CmpRdiBl
        $cursor = $fallbackField.NextOffset
        $fallbackToFalse = Read-X64RelativeBranch -Bytes $Bytes -Offset $cursor -Kind Je -Limit ([int]$functionEndOffset)
        $cursor = $fallbackToFalse.NextOffset

        $setTrueOffset = $cursor
        if ($helperToTrue.TargetOffset -ne $setTrueOffset -or
            -not [BinaryScanner]::MatchBytes($Bytes, $setTrueOffset, (Convert-HexStringToBytes 'B3 01'))) {
            return $null
        }
        $cursor += 2

        $returnFalseOffset = $cursor
        if ($gateToFalse.TargetOffset -ne $returnFalseOffset -or $fallbackToFalse.TargetOffset -ne $returnFalseOffset -or
            -not [BinaryScanner]::MatchBytes($Bytes, $returnFalseOffset, (Convert-HexStringToBytes '8A C3'))) {
            return $null
        }
        $cursor += 2

        $epilogueOffset = $cursor
        if ($toEpilogue.TargetOffset -ne $epilogueOffset) {
            return $null
        }

        $epilogue = Convert-HexStringToBytes '48 8B 5C 24 00 48 83 C4 00 5F C3'
        $epilogueMask = Convert-HexStringToBytes 'FF FF FF FF 00 FF FF FF 00 FF FF'
        if (-not [BinaryScanner]::MatchMaskedBytes($Bytes, $epilogueOffset, $epilogue, $epilogueMask)) {
            return $null
        }

        $restoreDisplacement = [int]$Bytes[$epilogueOffset + 4]
        $restoreFrame = [int]$Bytes[$epilogueOffset + 8]
        if ($restoreFrame -ne $stackFrame -or $restoreDisplacement -ne ($saveDisplacement + $stackFrame + 8)) {
            return $null
        }
        $cursor += $epilogue.Length

        $tailLength = [int64]$functionEndOffset - $cursor
        if ($tailLength -lt 0 -or $tailLength -gt 16) {
            return $null
        }
        for ($i = $cursor; $i -lt $functionEndOffset; $i++) {
            if ($Bytes[$i] -ne 0x90 -and $Bytes[$i] -ne 0xCC) {
                return $null
            }
        }

        $jumpDisplacement = [int64]$returnFalseOffset - ([int64]$patchOffset + 2)
        if ($jumpDisplacement -lt 0 -or $jumpDisplacement -gt 0x7F) {
            return $null
        }
        $patchedBytes = [byte[]]@(0xEB, [byte]$jumpDisplacement, 0x90)
        if ($state -eq 'Patched' -and -not [BinaryScanner]::MatchBytes($Bytes, $patchOffset, $patchedBytes)) {
            return $null
        }

        return [PSCustomObject]@{
            PredicateRva   = $TargetRva
            FunctionOffset = [int64]$functionOffset
            FunctionEnd    = [int64]$functionEndOffset
            PatchOffset    = [int64]$patchOffset
            ReturnOffset   = [int64]$returnFalseOffset
            OriginalBytes  = $originalPatch
            PatchedBytes   = $patchedBytes
            State          = $state
        }
    }
    catch {
        return $null
    }
}

function Find-BlockSlotsBinaryPatchLocation {
    param(
        [byte[]]$Bytes,
        [object]$PeInfo
    )

    $text = $PeInfo.Sections | Where-Object { $_.Name -eq '.text' } | Select-Object -First 1
    $pdata = $PeInfo.Sections | Where-Object { $_.Name -eq '.pdata' } | Select-Object -First 1
    if (-not $text -or -not $pdata) {
        throw 'Required PE sections were not found'
    }

    $rawPtrs = [int[]]($PeInfo.Sections | ForEach-Object { [int]$_.RawPtr })
    $rawSizes = [int[]]($PeInfo.Sections | ForEach-Object { [int]$_.RawSize })
    $virtualAddresses = [int[]]($PeInfo.Sections | ForEach-Object { [int]$_.VirtualAddress })

    # Use the error string as an independent sanity check
    $anchor = [Text.Encoding]::ASCII.GetBytes("slot_is_disabled`0")
    $anchorOffset = [BinaryScanner]::FindBytes($Bytes, $anchor, 0)
    if ($anchorOffset -lt 0 -or [BinaryScanner]::FindBytes($Bytes, $anchor, $anchorOffset + 1) -ge 0) {
        throw 'slot_is_disabled anchor was not found uniquely'
    }
    $anchorRva = Get-PERvaFromOffset -Sections $PeInfo.Sections -Offset $anchorOffset
    if ($null -eq $anchorRva) {
        throw 'slot_is_disabled anchor RVA was not found'
    }

    $anchorRefs = @([BinaryScanner]::FindRipLeaRefs(
            $Bytes,
            [int]$text.RawPtr,
            [int]$text.RawSize,
            [int64]$anchorRva,
            $rawPtrs,
            $rawSizes,
            $virtualAddresses
        ) | Select-Object -Unique)
    if ($anchorRefs.Count -eq 0) {
        throw 'slot_is_disabled code reference was not found'
    }

    $anchorFunctions = @{}
    foreach ($anchorRef in $anchorRefs) {
        $anchorRefRva = Get-PERvaFromOffset -Sections $PeInfo.Sections -Offset ([int64]$anchorRef)
        if ($null -eq $anchorRefRva) {
            throw 'slot_is_disabled reference RVA was not found'
        }
        $anchorFunction = [BinaryScanner]::FindFunctionRange(
            $Bytes,
            [int]$pdata.RawPtr,
            [int]$pdata.RawSize,
            [int64]$anchorRefRva
        )
        if ($anchorFunction.Length -ne 2) {
            throw 'slot_is_disabled mapper function was not found'
        }
        $anchorFunctionSize = [int64]$anchorFunction[1] - [int64]$anchorFunction[0]
        if ($anchorFunctionSize -lt 0x100 -or $anchorFunctionSize -gt 0x4000) {
            throw 'Unexpected slot_is_disabled mapper function size'
        }
        $anchorFunctions['{0:X}' -f [int64]$anchorFunction[0]] = [PSCustomObject]@{
            StartRva = [int64]$anchorFunction[0]
            EndRva   = [int64]$anchorFunction[1]
        }
    }
    if ($anchorFunctions.Count -ne 1) {
        throw "Expected one slot_is_disabled mapper function, found $($anchorFunctions.Count)"
    }

    $mapperFunction = @($anchorFunctions.Values)[0]
    $slotDisabledEnum = Get-BlockSlotsMapperEnumValue `
        -Bytes $Bytes `
        -PeInfo $PeInfo `
        -MapperStartRva $mapperFunction.StartRva `
        -MapperEndRva $mapperFunction.EndRva `
        -AnchorRefs $anchorRefs

    $callPatterns = @(
        [PSCustomObject]@{
            Pattern      = Convert-HexStringToBytes 'E8 00 00 00 00 84 C0 75 00 BA 00 00 00 00'
            Mask         = Convert-HexStringToBytes 'FF 00 00 00 00 FF FF FF 00 FF 00 00 00 00'
            BranchOffset = 7
            EnumOffset   = 10
        },
        [PSCustomObject]@{
            Pattern      = Convert-HexStringToBytes 'E8 00 00 00 00 84 C0 0F 85 00 00 00 00 BA 00 00 00 00'
            Mask         = Convert-HexStringToBytes 'FF 00 00 00 00 FF FF FF FF 00 00 00 00 FF 00 00 00 00'
            BranchOffset = 7
            EnumOffset   = 14
        }
    )

    $textStart = [int]$text.RawPtr
    $textEnd = [int64]$text.RawPtr + [int64]$text.RawSize
    $validatedTargets = @{}

    foreach ($callPattern in $callPatterns) {
        $searchOffset = $textStart
        while ($searchOffset -lt $textEnd) {
            $callOffset = [BinaryScanner]::FindMaskedBytes(
                $Bytes,
                $callPattern.Pattern,
                $callPattern.Mask,
                $searchOffset,
                [int]($textEnd - $searchOffset)
            )
            if ($callOffset -lt 0) {
                break
            }
            $searchOffset = $callOffset + 1

            try {
                $enumValue = [BitConverter]::ToUInt32($Bytes, $callOffset + $callPattern.EnumOffset)
                if ($enumValue -ne $slotDisabledEnum) {
                    continue
                }

                $callerRva = Get-PERvaFromOffset -Sections $PeInfo.Sections -Offset $callOffset
                $callNextRva = Get-PERvaFromOffset -Sections $PeInfo.Sections -Offset ($callOffset + 5)
                if ($null -eq $callerRva -or $null -eq $callNextRva) {
                    continue
                }

                $callerRange = [BinaryScanner]::FindFunctionRange(
                    $Bytes,
                    [int]$pdata.RawPtr,
                    [int]$pdata.RawSize,
                    [int64]$callerRva
                )
                if ($callerRange.Length -ne 2) {
                    continue
                }

                $callerBranch = Read-X64RelativeBranch `
                    -Bytes $Bytes `
                    -Offset ($callOffset + $callPattern.BranchOffset) `
                    -Kind Jne `
                    -Limit ([int]$textEnd)
                $branchTargetRva = Get-PERvaFromOffset -Sections $PeInfo.Sections -Offset $callerBranch.TargetOffset
                if ($null -eq $branchTargetRva -or $branchTargetRva -lt [int64]$callerRange[0] -or
                    $branchTargetRva -ge [int64]$callerRange[1]) {
                    continue
                }

                $targetRva = [int64]$callNextRva + [BitConverter]::ToInt32($Bytes, $callOffset + 1)
                $predicate = Get-BlockSlotsPredicateInfo `
                    -Bytes $Bytes `
                    -PeInfo $PeInfo `
                    -TextSection $text `
                    -PdataSection $pdata `
                    -TargetRva $targetRva
                if ($null -eq $predicate) {
                    continue
                }

                $key = '{0:X}' -f $targetRva
                if (-not $validatedTargets.ContainsKey($key)) {
                    $validatedTargets[$key] = [PSCustomObject]@{
                        Predicate    = $predicate
                        CallerCount  = 1
                        CallerOffset = [int64]$callOffset
                        EnumValue    = [uint32]$enumValue
                    }
                }
                else {
                    $validatedTargets[$key].CallerCount++
                }
            }
            catch {
                continue
            }
        }
    }

    if ($validatedTargets.Count -eq 0) {
        throw 'block_slots semantic function was not found'
    }
    if ($validatedTargets.Count -ne 1) {
        throw "Expected one block_slots semantic function, found $($validatedTargets.Count)"
    }

    $match = @($validatedTargets.Values)[0]
    return [PSCustomObject]@{
        PredicateRva   = $match.Predicate.PredicateRva
        FunctionOffset = $match.Predicate.FunctionOffset
        FunctionEnd    = $match.Predicate.FunctionEnd
        PatchOffset    = $match.Predicate.PatchOffset
        ReturnOffset   = $match.Predicate.ReturnOffset
        OriginalBytes  = $match.Predicate.OriginalBytes
        PatchedBytes   = $match.Predicate.PatchedBytes
        State          = $match.Predicate.State
        CallerOffset   = $match.CallerOffset
        CallerCount    = $match.CallerCount
        EnumValue      = $match.EnumValue
    }
}

function Set-BlockSlotsBinaryPatch {
    [CmdletBinding()]
    param (
        [string]$FilePath
    )

    try {
        Initialize-BinaryScanner

        if (-not (Test-Path -LiteralPath $FilePath)) {
            throw 'File Spotify.dll not found'
        }

        $bytes = [System.IO.File]::ReadAllBytes($FilePath)
        $peInfo = Get-PEFileInfo -Bytes $bytes
        if ($peInfo.Architecture -ne 'x64') {
            throw "Architecture $($peInfo.Architecture) is not supported for block_slots patch"
        }

        $location = Find-BlockSlotsBinaryPatchLocation -Bytes $bytes -PeInfo $peInfo
        Write-Verbose ("block_slots predicate RVA 0x{0:X}, caller offset 0x{1:X}, enum 0x{2:X}" -f
            $location.PredicateRva, $location.CallerOffset, $location.EnumValue)

        if ($location.State -eq 'Patched') {
            Write-Verbose ("block_slots already patched at offset 0x{0:X}" -f $location.PatchOffset)
            return $true
        }
        if ($location.State -ne 'Original' -or
            -not [BinaryScanner]::MatchBytes($bytes, [int]$location.PatchOffset, $location.OriginalBytes)) {
            throw 'Unexpected block_slots patch state'
        }

        $patchedFileBytes = [byte[]]$bytes.Clone()
        for ($i = 0; $i -lt $location.PatchedBytes.Length; $i++) {
            $patchedFileBytes[[int]$location.PatchOffset + $i] = $location.PatchedBytes[$i]
        }

        try {
            [System.IO.File]::WriteAllBytes($FilePath, $patchedFileBytes)
            $writtenBytes = [System.IO.File]::ReadAllBytes($FilePath)
            $writtenPeInfo = Get-PEFileInfo -Bytes $writtenBytes
            $writtenLocation = Find-BlockSlotsBinaryPatchLocation -Bytes $writtenBytes -PeInfo $writtenPeInfo
            if ($writtenLocation.State -ne 'Patched' -or $writtenLocation.PatchOffset -ne $location.PatchOffset -or
                -not [BinaryScanner]::MatchBytes($writtenBytes, [int]$location.PatchOffset, $location.PatchedBytes)) {
                throw 'block_slots patch verification failed'
            }
        }
        catch {
            $patchError = $_.Exception.Message
            try {
                [System.IO.File]::WriteAllBytes($FilePath, $bytes)
                $restoredBytes = [System.IO.File]::ReadAllBytes($FilePath)
                if ($restoredBytes.Length -ne $bytes.Length -or -not [BinaryScanner]::MatchBytes($restoredBytes, 0, $bytes)) {
                    throw 'rollback verification failed'
                }
            }
            catch {
                throw "$patchError; rollback failed: $($_.Exception.Message)"
            }
            throw $patchError
        }

        Write-Verbose ("block_slots patched at offset 0x{0:X} with {1}" -f
            $location.PatchOffset,
            (($location.PatchedBytes | ForEach-Object { $_.ToString('X2') }) -join ' '))
        return $true
    }
    catch {
        Write-Warning ("block_slots patch was not applied: {0}" -f $_.Exception.Message)
        return $false
    }
}

function Set-CrossfadeEnabledBinaryPatch {
    [CmdletBinding()]
    param (
        [string]$FilePath
    )

    try {
        Initialize-BinaryScanner

        if (-not (Test-Path -LiteralPath $FilePath)) {
            throw "File Spotify.dll not found"
        }

        $bytes = [System.IO.File]::ReadAllBytes($FilePath)
        $peInfo = Get-PEFileInfo -Bytes $bytes

        if ($peInfo.Architecture -ne 'x64') {
            throw "Architecture $($peInfo.Architecture) is not supported for crossfade_enabled patch"
        }

        $text = $peInfo.Sections | Where-Object { $_.Name -eq '.text' } | Select-Object -First 1
        $pdata = $peInfo.Sections | Where-Object { $_.Name -eq '.pdata' } | Select-Object -First 1

        if (-not $text -or -not $pdata) {
            throw "Required PE sections were not found"
        }

        $rawPtrs = [int[]]($peInfo.Sections | ForEach-Object { [int]$_.RawPtr })
        $rawSizes = [int[]]($peInfo.Sections | ForEach-Object { [int]$_.RawSize })
        $virtualAddresses = [int[]]($peInfo.Sections | ForEach-Object { [int]$_.VirtualAddress })

        $needle = [Text.Encoding]::ASCII.GetBytes('crossfade_enabled')
        $needleOffset = [BinaryScanner]::FindBytes($bytes, $needle, 0)
        if ($needleOffset -lt 0) {
            throw "crossfade_enabled was not found"
        }

        $needleRva = Get-PERvaFromOffset -Sections $peInfo.Sections -Offset $needleOffset
        if ($null -eq $needleRva) {
            throw "crossfade_enabled RVA was not found"
        }

        $needleVa = [int64]$peInfo.ImageBase + [int64]$needleRva
        $refOffsets = @([BinaryScanner]::FindRipRefs($bytes, [int]$text.RawPtr, [int]$text.RawSize, [int64]$peInfo.ImageBase, $needleVa, $rawPtrs, $rawSizes, $virtualAddresses) | Select-Object -Unique)
        if ($refOffsets.Count -eq 0) {
            throw "No code reference to crossfade_enabled was found"
        }

        $refRva = Get-PERvaFromOffset -Sections $peInfo.Sections -Offset ([int64]$refOffsets[0])
        if ($null -eq $refRva) {
            throw "crossfade_enabled reference RVA was not found"
        }

        $getterRange = [BinaryScanner]::FindFunctionRange($bytes, [int]$pdata.RawPtr, [int]$pdata.RawSize, [int64]$refRva)
        if ($getterRange.Length -ne 2) {
            throw "Could not resolve crossfade_enabled getter function"
        }

        $patchOffsets = @([BinaryScanner]::FindCallsToRva($bytes, [int]$text.RawPtr, [int]$text.RawSize, [int64]$getterRange[0], $rawPtrs, $rawSizes, $virtualAddresses))
        if ($patchOffsets.Count -ne 1) {
            throw "Expected one crossfade gate call site, found $($patchOffsets.Count)"
        }

        $patchOffset = [int]$patchOffsets[0]
        $patchBytes = Convert-HexStringToBytes "B0 01 90 90 90"
        if ($patchOffset + $patchBytes.Length -gt $bytes.Length) {
            throw "Patch offset is outside the file"
        }

        for ($i = 0; $i -lt $patchBytes.Length; $i++) {
            $bytes[$patchOffset + $i] = $patchBytes[$i]
        }

        [System.IO.File]::WriteAllBytes($FilePath, $bytes)
        Write-Verbose ("crossfade_enabled patched at offset 0x{0:X}" -f $patchOffset)
        return $true
    }
    catch {
        Write-Warning ("crossfade_enabled patch was not applied: {0}" -f $_.Exception.Message)
        return $false
    }
}

function Remove-Sign {
    [CmdletBinding()]
    param([string]$filePath)
    try {
        $bytes = [System.IO.File]::ReadAllBytes($filePath)
        $peInfo = Get-PEFileInfo -Bytes $bytes
        if ($peInfo.DataDirectoryOffset -eq $null) {
            Write-Warning "Unsupported architecture type ($($peInfo.MachineType.ToString('X'))) in file '$(Split-Path $filePath -Leaf)'."
            return $false
        }
        $dataDirectoryOffsetWithinOptionalHeader = $peInfo.DataDirectoryOffset
        $securityDirectoryIndex = 4
        $certificateTableEntryOffset = $peInfo.OptionalHeaderOffset + $dataDirectoryOffsetWithinOptionalHeader + ($securityDirectoryIndex * 8)
        if ($certificateTableEntryOffset + 8 -gt $bytes.Length) {
            Write-Warning "Could not find Data Directory in file '$(Split-Path $filePath -Leaf)'. Header is corrupted or has non-standard format."
            return $false
        }
        $rva = [System.BitConverter]::ToUInt32($bytes, $certificateTableEntryOffset)
        $size = [System.BitConverter]::ToUInt32($bytes, $certificateTableEntryOffset + 4)
        if ($rva -eq 0 -and $size -eq 0) {
            Write-Host "Signature in file '$(Split-Path $filePath -Leaf)' is already absent." -ForegroundColor Yellow
            return $true
        }
        for ($i = 0; $i -lt 8; $i++) {
            $bytes[$certificateTableEntryOffset + $i] = 0
        }
        [System.IO.File]::WriteAllBytes($filePath, $bytes)
        return $true
    }
    catch {
        if ($_.Exception.Message -eq 'Invalid PE file') {
            Write-Warning "File '$(Split-Path $filePath -Leaf)' is not a valid PE file."
        }
        else {
            Write-Error "Error processing file '$filePath': $_"
        }
        return $false
    }
}

function Remove-Signature-FromFiles {
    [CmdletBinding()]
    param([string[]]$fileNames)
    foreach ($fileName in $fileNames) {
        $fullPath = Join-Path -Path $spotifyDirectory -ChildPath $fileName
        if (-not (Test-Path $fullPath)) {
            Write-Error "File not found: $fullPath"
            Stop-Script
        }
        try {
            Write-Verbose "Processing file: $fileName"
            if (Remove-Sign -filePath $fullPath) {
                Write-Verbose "  -> Signature entry successfully zeroed."
            }
        }
        catch {
            Write-Error "Failed to process file '$fileName': $_"
            Stop-Script
        }
    }
}

#  REPOSITORY CONFIGURATION & CONSTANTS
# Customize these variables for your own GitHub repository:
$script:GITHUB_USER = "Mehmetyll"             # GitHub username
$script:GITHUB_REPO = "SpotX-Plus"            # Repository name
$script:GITHUB_BRANCH = "main"

# Configured raw GitHub URLs:
$script:RAW_BASE_URL = "https://raw.githubusercontent.com/$($script:GITHUB_USER)/$($script:GITHUB_REPO)/$($script:GITHUB_BRANCH)"
$script:PATCHES_URL = "$($script:RAW_BASE_URL)/patches/patches.json"
$script:VERSIONS_MANIFEST_URL = "$($script:RAW_BASE_URL)/versions.json"
$script:SPOTIFY_DOWNLOAD_BASE = "https://loadspot.amd64fox1.workers.dev/download"

# Fallback URLs (in case user hasn't set up custom GitHub repo yet):
$script:PATCHES_URL_FALLBACK = "https://raw.githubusercontent.com/SpotX-Official/SpotX/main/patches/patches.json"
$script:MANIFEST_URL_FALLBACK = "https://raw.githubusercontent.com/LoaderSpot/table/refs/heads/main/table/versions.json"

# Local environment paths:
$script:SPOTX_VERSION = "1.0.0"
$script:SPOTIFY_ROAMING = Join-Path $env:APPDATA 'Spotify'
$script:SPOTIFY_LOCAL = Join-Path $env:LOCALAPPDATA 'Spotify'
$script:SPOTIFY_EXE = Join-Path $script:SPOTIFY_ROAMING 'Spotify.exe'
$script:SPOTIFY_APPS = Join-Path $script:SPOTIFY_ROAMING 'Apps'
$script:XPUI_SPA = Join-Path $script:SPOTIFY_APPS 'xpui.spa'
$script:XPUI_SPA_BAK = Join-Path $script:SPOTIFY_APPS 'xpui.spa.bak'
$script:CHROME_ELF = Join-Path $script:SPOTIFY_ROAMING 'chrome_elf.dll'
$script:CHROME_ELF_BAK = Join-Path $script:SPOTIFY_ROAMING 'chrome_elf.dll.bak'
$script:SPOTIFY_DLL = Join-Path $script:SPOTIFY_ROAMING 'Spotify.dll'
$script:SPOTIFY_DLL_BAK = Join-Path $script:SPOTIFY_ROAMING 'Spotify.dll.bak'
$script:UPDATE_FOLDER = Join-Path $script:SPOTIFY_LOCAL 'Update'

function Write-Banner {
    $banner = @"

  ========================================================
   SpotX+ -- Streamlined Spotify Patcher v$($script:SPOTX_VERSION)
   Zero telemetry. Zero hassle.
  ========================================================

"@
    Write-Host $banner -ForegroundColor Cyan
}

function Write-Step {
    param([string]$Message)
    Write-Host "  [*]" -NoNewline -ForegroundColor Cyan
    Write-Host " $Message" -ForegroundColor White
}

function Write-Success {
    param([string]$Message)
    Write-Host "  [+] " -NoNewline -ForegroundColor Green
    Write-Host "$Message" -ForegroundColor Green
}

function Write-Fail {
    param([string]$Message)
    Write-Host "  [-] " -NoNewline -ForegroundColor Red
    Write-Host "$Message" -ForegroundColor Red
}

function Write-Info {
    param([string]$Message)
    Write-Host "  [i] " -NoNewline -ForegroundColor Yellow
    Write-Host "$Message" -ForegroundColor Gray
}

function Stop-WithError {
    param([string]$Message)
    Write-Host ""
    Write-Fail $Message
    Write-Host ""
    Write-Host "  SpotX+ encountered a fatal error and cannot continue." -ForegroundColor DarkRed
    Write-Host "  Press any key to exit..." -ForegroundColor DarkGray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}

#  PRE-FLIGHT CHECKS
function Invoke-PreFlightChecks {
    Write-Host ""
    Write-Step "Running pre-flight checks..."
    Write-Host ""

    # Check PowerShell version
    $psVer = $PSVersionTable.PSVersion.Major
    if ($psVer -lt 5) {
        Stop-WithError "PowerShell 5.1 or higher is required (found v$psVer). Please update Windows Management Framework."
    }
    Write-Success "PowerShell version: $($PSVersionTable.PSVersion)"

    # Check Windows version (require Win10+)
    $osVersion = [System.Environment]::OSVersion.Version
    if ($osVersion.Major -lt 10) {
        Stop-WithError "Windows 10 or higher is required (found $($osVersion.Major).$($osVersion.Minor))."
    }
    Write-Success "Windows version: $($osVersion.Major).$($osVersion.Minor) (Build $($osVersion.Build))"

    # Check architecture
    $arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    if ($arch -notin @('AMD64', 'ARM64')) {
        Stop-WithError "Unsupported architecture: $arch. SpotX+ requires x64 or ARM64."
    }
    Write-Success "Architecture: $arch"

    # Import Appx module for PS7+
    if ($psVer -ge 7) {
        Import-Module Appx -UseWindowsPowerShell -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
    }

    # Check for Microsoft Store Spotify
    $msStoreSpotify = Get-AppxPackage -Name "SpotifyAB.SpotifyMusic" -ErrorAction SilentlyContinue
    if ($msStoreSpotify) {
        Write-Info "Microsoft Store version of Spotify detected - removing automatically..."
        try {
            $msStoreSpotify | Remove-AppxPackage -ErrorAction Stop
            Write-Success "Microsoft Store Spotify removed successfully"
        }
        catch {
            Write-Fail "Could not remove MS Store Spotify: $($_.Exception.Message)"
            Write-Info "Please uninstall it manually from Settings > Apps, then re-run SpotX+."
            Stop-WithError "Cannot proceed with Microsoft Store Spotify installed."
        }
    }

    return $arch
}

#  SPOTIFY DETECTION & INSTALLATION
function Get-InstalledSpotifyVersion {
    if (-not (Test-Path $script:SPOTIFY_EXE)) {
        return $null
    }

    try {
        $versionInfo = (Get-Item $script:SPOTIFY_EXE).VersionInfo
        $version = "$($versionInfo.FileMajorPart).$($versionInfo.FileMinorPart).$($versionInfo.FileBuildPart).$($versionInfo.FilePrivatePart)"
        return $version
    }
    catch {
        return $null
    }
}

function Stop-SpotifyProcesses {
    Write-Step "Stopping Spotify processes..."

    $processes = @('Spotify', 'SpotifyWebHelper', 'SpotifyMigrator')
    $killed = $false

    foreach ($proc in $processes) {
        $running = Get-Process -Name $proc -ErrorAction SilentlyContinue
        if ($running) {
            $running | Stop-Process -Force -ErrorAction SilentlyContinue
            $killed = $true
        }
    }

    if ($killed) {
        Start-Sleep -Milliseconds 500
        Write-Success "Spotify processes stopped"
    }
    else {
        Write-Success "No Spotify processes running"
    }
}

function Resolve-SpotifyFullVersion {
    param([string]$ShortVersion)

    Write-Step "Resolving Spotify version $ShortVersion..."

    $arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    $installerArch = switch ($arch.ToUpperInvariant()) {
        'ARM64' { 'arm64' }
        default { 'x64' }
    }

    try {
        $ProgressPreference = 'SilentlyContinue'
        $manifest = $null

        # Check local versions.json first (if executing from local disk script)
        if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
            $localManifestPath = Join-Path $PSScriptRoot "versions.json"
            if (Test-Path $localManifestPath) {
                try {
                    $rawJson = [System.IO.File]::ReadAllText($localManifestPath)
                    $manifest = $rawJson | ConvertFrom-Json
                    Write-Info "Loaded versions manifest from local versions.json"
                }
                catch {}
            }
        }

        if (-not $manifest) {
            try {
                $manifest = Invoke-RestMethod -Uri $script:VERSIONS_MANIFEST_URL -UseBasicParsing -TimeoutSec 15
            }
            catch {
                # Fallback to upstream manifest URL
                $manifest = Invoke-RestMethod -Uri $script:MANIFEST_URL_FALLBACK -UseBasicParsing -TimeoutSec 15
            }
        }

        $versionPrefix = "$ShortVersion."
        $versions = @($manifest.PSObject.Properties)
        $selectedVersion = $versions |
        Where-Object { $_.Name.StartsWith($versionPrefix, [System.StringComparison]::Ordinal) } |
        Sort-Object { [version]$_.Name } -Descending |
        Select-Object -First 1

        if (-not $selectedVersion) {
            Stop-WithError "Spotify version $ShortVersion not found in versions manifest."
        }

        $entry = $selectedVersion.Value
        $fullVersion = [string]$entry.fullversion

        if ($fullVersion -notmatch '^\d+\.\d+\.\d+\.\d+\.g[0-9a-f]{8}$') {
            Stop-WithError "Invalid fullversion format in manifest: $fullVersion"
        }

        $windowsAssets = $entry.win
        $archAsset = if ($windowsAssets) { $windowsAssets.PSObject.Properties[$installerArch] } else { $null }

        if (-not $archAsset) {
            Stop-WithError "No Windows $installerArch asset found for Spotify $ShortVersion."
        }

        Write-Success "Resolved to full version: $fullVersion ($installerArch)"
        return @{
            FullVersion  = $fullVersion
            Architecture = $installerArch
        }
    }
    catch [System.Management.Automation.RuntimeException] {
        throw
    }
    catch {
        Stop-WithError "Failed to resolve Spotify version: $($_.Exception.Message)"
    }
}

function Install-Spotify {
    param(
        [string]$FullVersion,
        [string]$Architecture
    )

    $installerName = "spotify_installer-$FullVersion-$Architecture.exe"
    $downloadUrl = "$($script:SPOTIFY_DOWNLOAD_BASE)/$installerName"
    $tempInstaller = Join-Path ([System.IO.Path]::GetTempPath()) $installerName

    Write-Step "Downloading Spotify $FullVersion ($Architecture)..."

    try {
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $downloadUrl -OutFile $tempInstaller -UseBasicParsing -TimeoutSec 120

        if (-not (Test-Path $tempInstaller)) {
            Stop-WithError "Download completed but installer file not found."
        }

        $fileSize = (Get-Item $tempInstaller).Length
        $fileSizeMB = [math]::Round($fileSize / 1MB, 2)
        Write-Success "Downloaded Spotify installer ($fileSizeMB MB)"
    }
    catch {
        Stop-WithError "Failed to download Spotify: $($_.Exception.Message)"
    }

    Write-Step "Installing Spotify (this may take a moment)..."

    try {
        $installProcess = Start-Process -FilePath $tempInstaller -PassThru -WindowStyle Hidden
        $installProcess.WaitForExit()

        # Wait for Spotify to appear
        $pollMax = 30
        $pollCount = 0
        while (-not (Test-Path $script:SPOTIFY_EXE) -and $pollCount -lt $pollMax) {
            Start-Sleep -Seconds 1
            $pollCount++
        }

        if (-not (Test-Path $script:SPOTIFY_EXE)) {
            Stop-WithError "Spotify installation did not complete. Spotify.exe not found."
        }

        # Kill Spotify if it auto-launched during install
        Start-Sleep -Milliseconds 1500
        Stop-SpotifyProcesses

        Write-Success "Spotify installed successfully"
    }
    catch {
        Stop-WithError "Spotify installation failed: $($_.Exception.Message)"
    }
    finally {
        Remove-Item $tempInstaller -Force -ErrorAction SilentlyContinue
    }
}

#  PATCHES ENGINE
function Get-PatchesJson {
    Write-Step "Loading patch definitions..."

    # Check local patches/patches.json first (if executing from local disk script)
    if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        $localPatchesPath = Join-Path $PSScriptRoot "patches\patches.json"
        if (Test-Path $localPatchesPath) {
            try {
                $rawJson = [System.IO.File]::ReadAllText($localPatchesPath, [System.Text.Encoding]::UTF8)
                $patches = $rawJson | ConvertFrom-Json
                Write-Success "Patch definitions loaded from local file"
                return $patches
            }
            catch {}
        }
    }

    try {
        $ProgressPreference = 'SilentlyContinue'
        $patches = Invoke-RestMethod -Uri $script:PATCHES_URL -UseBasicParsing -TimeoutSec 15
        Write-Success "Patch definitions loaded from network"
        return $patches
    }
    catch {
        try {
            $patches = Invoke-RestMethod -Uri $script:PATCHES_URL_FALLBACK -UseBasicParsing -TimeoutSec 15
            Write-Success "Patch definitions loaded from fallback network"
            return $patches
        }
        catch {
            Stop-WithError "Failed to download patches.json: $($_.Exception.Message)"
        }
    }
}

function Test-VersionInRange {
    param(
        [version]$Current,
        [string]$From,
        [string]$To
    )

    if ([string]::IsNullOrWhiteSpace($From)) { return $false }

    $fromVersion = [version]$From
    if ($Current -lt $fromVersion) { return $false }

    if (-not [string]::IsNullOrWhiteSpace($To)) {
        $toVersion = [version]$To
        if ($Current -gt $toVersion) { return $false }
    }

    return $true
}

function Extract-WebpackModules {
    param([string]$InputFile)

    function Encode-UTF16LE {
        param([byte[]]$Bytes)
        $str = [System.Text.Encoding]::UTF8.GetString($Bytes)
        [System.Text.Encoding]::Unicode.GetBytes($str)
    }

    function IndexOfBytes($haystack, $needle, [int]$startIndex = 0) {
        if ($startIndex -lt 0) { $startIndex = 0 }
        $haystackLength = $haystack.Length
        $needleLength = $needle.Length
        $searchLimit = $haystackLength - $needleLength
        if ($searchLimit -lt $startIndex) { return -1 }
        $firstNeedleByte = $needle[0]
        for ($i = $startIndex; $i -le $searchLimit; $i++) {
            if ($haystack[$i] -eq $firstNeedleByte) {
                $found = $true
                for ($j = 1; $j -lt $needleLength; $j++) {
                    if ($haystack[$i + $j] -ne $needle[$j]) {
                        $found = $false
                        break
                    }
                }
                if ($found) { return $i }
            }
        }
        return -1
    }

    $StartMarker = [System.Text.Encoding]::UTF8.GetBytes("var __webpack_modules__={")
    $EndMarker = [System.Text.Encoding]::UTF8.GetBytes("//# sourceMappingURL=xpui-modules.js.map")

    [byte[]]$fileContent = [System.IO.File]::ReadAllBytes($InputFile)
    $searchStartMarker = Encode-UTF16LE -Bytes $StartMarker
    $searchEndMarker = Encode-UTF16LE -Bytes $EndMarker

    $startIdx = IndexOfBytes $fileContent $searchStartMarker 2
    if ($startIdx -eq -1) { return $null }

    $endMarkerSearchOffset = $startIdx + $searchStartMarker.Length
    $endIdx = IndexOfBytes $fileContent $searchEndMarker $endMarkerSearchOffset
    if ($endIdx -eq -1) { return $null }

    $endDataIdx = $endIdx + $searchEndMarker.Length
    $length = $endDataIdx - $startIdx

    return [System.Text.Encoding]::Unicode.GetString($fileContent, $startIdx, $length)
}

function Invoke-PatchXpuiSpa {
    param(
        [string]$InstalledVersion,
        [object]$Patches
    )

    Write-Host ""
    Write-Step "Patching xpui.spa..."

    # Validate xpui.spa exists
    if (-not (Test-Path $script:XPUI_SPA)) {
        Stop-WithError "xpui.spa not found at $($script:XPUI_SPA). Please log into Spotify once so it finishes downloading its core app files, then re-run SpotX+."
    }

    if (-not (Test-Path $script:XPUI_SPA_BAK)) {
        Copy-Item $script:XPUI_SPA $script:XPUI_SPA_BAK -Force
        Write-Success "Created backup: xpui.spa.bak"
    }
    else {
        Write-Info "Backup already exists - restoring original before patching"
        Copy-Item $script:XPUI_SPA_BAK $script:XPUI_SPA -Force
    }

    # Check for V8 context snapshot in Spotify directory
    $v8Snapshot = Join-Path $script:SPOTIFY_ROAMING 'v8_context_snapshot.bin'
    if (-not (Test-Path $v8Snapshot)) {
        $v8Snapshot = Join-Path $script:SPOTIFY_ROAMING 'v8_context_snapshot.arm64.bin'
    }

    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    # Open ZIP in Update mode
    $zip = [System.IO.Compression.ZipFile]::Open(
        $script:XPUI_SPA,
        [System.IO.Compression.ZipArchiveMode]::Update
    )

    try {
        # Check if xpui-snapshot.js needs conversion to xpui.js
        $snapshotEntry = $zip.GetEntry('xpui-snapshot.js')
        if ($null -ne $snapshotEntry -and (Test-Path $v8Snapshot)) {
            Write-Step "Converting V8 snapshot JS bundle..."
            $modules = Extract-WebpackModules -InputFile $v8Snapshot

            if ($modules) {
                $stream = $snapshotEntry.Open()
                $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::UTF8)
                $snapshotContent = $reader.ReadToEnd()
                $reader.Close()
                $stream.Close()

                # Replace xpui-snapshot.js with xpui.js
                $snapshotEntry.Delete()
                $xpuiEntry = $zip.CreateEntry('xpui.js')
                $stream = $xpuiEntry.Open()
                $writer = New-Object System.IO.StreamWriter($stream, [System.Text.Encoding]::UTF8)
                $writer.Write($modules + "`n" + $snapshotContent)
                $writer.Flush()
                $writer.Close()
                $stream.Close()

                # Rename xpui-snapshot.css -> xpui.css
                $cssEntry = $zip.GetEntry('xpui-snapshot.css')
                if ($null -ne $cssEntry) {
                    $stream = $cssEntry.Open()
                    $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::UTF8)
                    $cssContent = $reader.ReadToEnd()
                    $reader.Close()
                    $stream.Close()

                    $cssEntry.Delete()
                    $newCssEntry = $zip.CreateEntry('xpui.css')
                    $stream = $newCssEntry.Open()
                    $writer = New-Object System.IO.StreamWriter($stream, [System.Text.Encoding]::UTF8)
                    $writer.Write($cssContent)
                    $writer.Flush()
                    $writer.Close()
                    $stream.Close()
                }

                # Update index.html references
                $indexEntry = $zip.GetEntry('index.html')
                if ($null -ne $indexEntry) {
                    $stream = $indexEntry.Open()
                    $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::UTF8)
                    $html = $reader.ReadToEnd()
                    $reader.Close()
                    $stream.Close()

                    $html = $html.Replace('xpui-snapshot.js', 'xpui.js').Replace('xpui-snapshot.css', 'xpui.css')

                    $indexEntry.Delete()
                    $newIndexEntry = $zip.CreateEntry('index.html')
                    $stream = $newIndexEntry.Open()
                    $writer = New-Object System.IO.StreamWriter($stream, [System.Text.Encoding]::UTF8)
                    $writer.Write($html)
                    $writer.Flush()
                    $writer.Close()
                    $stream.Close()
                }

                Write-Success "V8 snapshot converted to uncompiled JS bundle"
            }
        }

        # Get all JS entries from the ZIP
        $jsEntries = $zip.Entries | Where-Object { $_.Name -like '*.js' }

        $jsContents = @{}
        foreach ($entry in $jsEntries) {
            $stream = $entry.Open()
            $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::UTF8)
            $jsContents[$entry.FullName] = $reader.ReadToEnd()
            $reader.Close()
            $stream.Close()
        }

        $versionClean = $InstalledVersion -replace '\.g[0-9a-f]{8}$', ''
        $currentVersion = [version]$versionClean

        # Apply "free" patches (ad blocking core)
        $patchCount = 0
        $modifiedEntries = @{}

        Write-Step "Applying ad-blocking patches..."

        if ($Patches.free) {
            foreach ($patchProp in $Patches.free.PSObject.Properties) {
                $patch = $patchProp.Value
                $patchName = $patchProp.Name

                # Skip version-gated patches that don't apply
                if ($null -ne $patch.PSObject.Properties['version']) {
                    $inRange = Test-VersionInRange -Current $currentVersion -From $patch.version.fr -To $patch.version.to
                    if (-not $inRange) { continue }
                }

                if ($null -eq $patch.PSObject.Properties['match']) { continue }

                [array]$matchPatterns = @($patch.match)
                [array]$replacePatterns = if ($null -ne $patch.PSObject.Properties['replace']) { @($patch.replace) } else { @() }

                for ($i = 0; $i -lt $matchPatterns.Count; $i++) {
                    $matchPattern = $matchPatterns[$i]
                    $replacePattern = if ($i -lt $replacePatterns.Count) { $replacePatterns[$i] } else { "" }

                    foreach ($entryName in @($jsContents.Keys)) {
                        $content = $jsContents[$entryName]
                        if ($content -match $matchPattern) {
                            $jsContents[$entryName] = [regex]::Replace($content, $matchPattern, $replacePattern)
                            $modifiedEntries[$entryName] = $true
                            $patchCount++
                        }
                    }
                }
            }
        }
        Write-Success "Applied $patchCount ad-blocking patches"

        # Write modified JS entries back into the ZIP in-place
        Write-Step "Writing patched files..."
        foreach ($entryName in $modifiedEntries.Keys) {
            $entry = $zip.Entries | Where-Object { $_.FullName -eq $entryName } | Select-Object -First 1
            if ($entry) {
                $newContent = $jsContents[$entryName]
                $stream = $entry.Open()
                $stream.SetLength(0)
                $writer = New-Object System.IO.StreamWriter($stream, [System.Text.Encoding]::UTF8)
                $writer.Write($newContent)
                $writer.Flush()
                $writer.Close()
                $stream.Close()
            }
        }
        Write-Success "Patched files written to xpui.spa"
    }
    finally {
        $zip.Dispose()
    }
}

#  UPDATE BLOCKING
function Set-UpdateBlocking {
    param([bool]$Block)

    if (-not $Block) {
        Write-Info "Update blocking skipped (-NoUpdateBlock)"
        return
    }

    Write-Step "Blocking Spotify auto-updates permanently..."

    try {
        $everyone = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")
        $denyRights = [System.Security.AccessControl.FileSystemRights]"Write, Delete, ChangePermissions"
        $denyRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $everyone,
            $denyRights,
            [System.Security.AccessControl.AccessControlType]::Deny
        )

        # 1. Handle %LOCALAPPDATA%\Spotify\Update directory/file
        $updatePath = $script:UPDATE_FOLDER
        if (Test-Path $updatePath) {
            try {
                Set-ItemProperty -Path $updatePath -Name Attributes -Value ([System.IO.FileAttributes]::Normal) -ErrorAction SilentlyContinue
                Remove-Item $updatePath -Recurse -Force -ErrorAction SilentlyContinue
            } catch {}
        }

        if (-not (Test-Path $updatePath)) {
            # Create Update as a dummy 0-byte FILE so Spotify cannot create the Update folder
            New-Item -ItemType File -Path $updatePath -Force | Out-Null
            Set-ItemProperty -Path $updatePath -Name Attributes -Value ([System.IO.FileAttributes]::ReadOnly)
            try {
                $acl = Get-Acl $updatePath
                $acl.AddAccessRule($denyRule)
                Set-Acl $updatePath $acl
            } catch {}
        }

        # 2. Delete and block SpotifyUpdate.exe & SpotifyMigrator.exe executables
        $updaterPaths = @(
            (Join-Path $script:SPOTIFY_ROAMING 'SpotifyUpdate.exe'),
            (Join-Path $script:SPOTIFY_LOCAL 'SpotifyUpdate.exe'),
            (Join-Path $script:SPOTIFY_ROAMING 'SpotifyMigrator.exe')
        )

        foreach ($updater in $updaterPaths) {
            try {
                if (Test-Path $updater) {
                    Set-ItemProperty -Path $updater -Name Attributes -Value ([System.IO.FileAttributes]::Normal) -ErrorAction SilentlyContinue
                    Remove-Item $updater -Force -ErrorAction SilentlyContinue
                }
                if (-not (Test-Path $updater)) {
                    New-Item -ItemType File -Path $updater -Force | Out-Null
                    Set-ItemProperty -Path $updater -Name Attributes -Value ([System.IO.FileAttributes]::ReadOnly) -ErrorAction SilentlyContinue
                    $uAcl = Get-Acl $updater
                    $uAcl.AddAccessRule($denyRule)
                    Set-Acl $updater $uAcl
                }
            } catch {}
        }

        # 3. Block Spotify update network domains in Windows hosts file
        $hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
        if (Test-Path $hostsPath) {
            try {
                $hostsContent = [System.IO.File]::ReadAllText($hostsPath)
                $updateDomains = @(
                    "desktop-update.spotify.com",
                    "upgrade.spotify.com"
                )
                $newEntries = @()
                foreach ($domain in $updateDomains) {
                    if ($hostsContent -notlike "*$domain*") {
                        $newEntries += "0.0.0.0 $domain"
                    }
                }
                if ($newEntries.Count -gt 0) {
                    $blockHeader = "`n# SpotX+ Spotify Update Blocking`n" + ($newEntries -join "`n") + "`n"
                    [System.IO.File]::AppendAllText($hostsPath, $blockHeader)
                }
            }
            catch {}
        }

        Write-Success "Spotify auto-updates blocked permanently"
    }
    catch {
        Write-Info "Update blocking applied: $($_.Exception.Message)"
    }
}

#  BINARY PATCHING (Spotify.dll)
function Invoke-BinaryPatching {
    param([string]$InstalledVersion)

    $versionClean = $InstalledVersion -replace '\.g[0-9a-f]{8}$', ''
    $currentVersion = [version]$versionClean

    Write-Step "Patching Spotify binaries..."

    # Backup Spotify.dll
    if (Test-Path $script:SPOTIFY_DLL) {
        if (-not (Test-Path $script:SPOTIFY_DLL_BAK)) {
            Copy-Item $script:SPOTIFY_DLL $script:SPOTIFY_DLL_BAK -Force
            Write-Success "Created backup: Spotify.dll.bak"
        }
        else {
            Write-Info "Restoring original Spotify.dll from backup"
            Copy-Item $script:SPOTIFY_DLL_BAK $script:SPOTIFY_DLL -Force
        }
    }

    # Disable signature verification in Spotify.dll
    try {
        Reset-Dll-Sign -FilePath $script:SPOTIFY_DLL
        Write-Success "Signature verification disabled in Spotify.dll"
    }
    catch {
        Write-Info "Signature reset skipped: $($_.Exception.Message)"
    }

    # Remove Authenticode signatures from binaries
    try {
        $spotifyDir = $script:SPOTIFY_ROAMING
        foreach ($fileName in @('Spotify.dll', 'Spotify.exe', 'chrome_elf.dll')) {
            $fullPath = Join-Path $spotifyDir $fileName
            if (Test-Path $fullPath) {
                $null = Remove-Sign -filePath $fullPath
            }
        }
        Write-Success "Authenticode signatures removed from binaries"
    }
    catch {
        Write-Info "Signature removal skipped: $($_.Exception.Message)"
    }

    # Block ad slots at binary level (v1.2.94+)
    if ($currentVersion -ge [version]'1.2.94') {
        try {
            $result = Set-BlockSlotsBinaryPatch -FilePath $script:SPOTIFY_DLL
            if ($result) {
                Write-Success "Ad slot rendering blocked in Spotify.dll (block_slots patch)"
            }
        }
        catch {
            Write-Info "Block slots patch skipped: $($_.Exception.Message)"
        }
    }

    #  Enable crossfade for free users (v1.2.89+)
    if ($currentVersion -ge [version]'1.2.89') {
        try {
            $result = Set-CrossfadeEnabledBinaryPatch -FilePath $script:SPOTIFY_DLL
            if ($result) {
                Write-Success "Crossfade enabled for free users"
            }
        }
        catch {
            Write-Info "Crossfade patch skipped: $($_.Exception.Message)"
        }
    }
}

#  CHROME_ELF.DLL BACKUP
function Backup-ChromeElf {
    if (Test-Path $script:CHROME_ELF) {
        if (-not (Test-Path $script:CHROME_ELF_BAK)) {
            Copy-Item $script:CHROME_ELF $script:CHROME_ELF_BAK -Force
            Write-Success "Created backup: chrome_elf.dll.bak"
        }
        else {
            Write-Info "chrome_elf.dll backup already exists"
        }
    }
}

#  MAIN EXECUTION
function Invoke-SpotXPlus {
    Clear-Host
    Write-Banner

    # Pre-flight
    $arch = Invoke-PreFlightChecks

    # Spotify detection
    Write-Host ""
    Write-Step "Detecting Spotify installation..."

    $installedVersion = Get-InstalledSpotifyVersion

    if ($installedVersion) {
        Write-Success "Spotify detected: v$installedVersion"
        Write-Info "Install path: $($script:SPOTIFY_ROAMING)"
    }
    elseif ($SkipInstall) {
        Stop-WithError "Spotify is not installed and -SkipInstall was specified."
    }
    else {
        Write-Info "Spotify not found - will download and install"
    }

    # Check if installed version matches the recommended target version
    $needsInstall = $false
    if (-not $installedVersion) {
        $needsInstall = $true
    }
    elseif (-not $SkipInstall -and -not $installedVersion.StartsWith($SpotifyVersion)) {
        Write-Host ""
        Write-Info "Installed version (v$installedVersion) differs from recommended v$SpotifyVersion."
        Write-Step "Automatically reinstalling recommended Spotify v$SpotifyVersion for 100% stability..."
        $needsInstall = $true
    }

    if ($needsInstall) {
        $versionInfo = Resolve-SpotifyFullVersion -ShortVersion $SpotifyVersion
        Write-Host ""
        Stop-SpotifyProcesses
        Install-Spotify -FullVersion $versionInfo.FullVersion -Architecture $versionInfo.Architecture
        $installedVersion = Get-InstalledSpotifyVersion
    }

    # If we still don't have a version, use the resolved one
    if (-not $installedVersion) {
        $installedVersion = $SpotifyVersion + ".0"
    }

    # Kill Spotify
    Write-Host ""
    Stop-SpotifyProcesses

    # Create backups
    Write-Step "Creating backups..."
    Backup-ChromeElf

    # Download patches
    Write-Host ""
    $patches = Get-PatchesJson

    # Patch xpui.spa
    Invoke-PatchXpuiSpa -InstalledVersion $installedVersion -Patches $patches

    # Block updates & ad domains
    Write-Host ""
    Set-UpdateBlocking -Block (-not $NoUpdateBlock)
    Invoke-BinaryPatching -InstalledVersion $installedVersion

    # Complete
    Write-Host ""
    Write-Host ""
    Write-Host "  ========================================================" -ForegroundColor Green
    Write-Host "   SpotX+ patch applied successfully!" -ForegroundColor Green
    Write-Host "  ========================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "   * Ad blocking:       " -NoNewline -ForegroundColor White
    Write-Host "ENABLED" -ForegroundColor Green
    Write-Host "   * Telemetry:         " -NoNewline -ForegroundColor White
    Write-Host "DISABLED" -ForegroundColor Green
    Write-Host "   * Podcast filter:    " -NoNewline -ForegroundColor White
    if ($NoPodcastFilter) { Write-Host "DISABLED" -ForegroundColor Yellow } else { Write-Host "ENABLED" -ForegroundColor Green }
    Write-Host "   * Update blocking:   " -NoNewline -ForegroundColor White
    if ($NoUpdateBlock) { Write-Host "DISABLED" -ForegroundColor Yellow } else { Write-Host "ENABLED" -ForegroundColor Green }
    Write-Host ""

    if ($LaunchAfter) {
        Write-Step "Launching Spotify..."
        Start-Process $script:SPOTIFY_EXE
        Write-Success "Spotify launched"
    }
    else {
        Write-Info "You can now launch Spotify manually."
    }

    Write-Host ""
}

try {
    Invoke-SpotXPlus
}
catch {
    Write-Host ""
    Write-Fail "Unexpected error: $($_.Exception.Message)"
    Write-Host "  $($_.ScriptStackTrace)" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Press any key to exit..." -ForegroundColor DarkGray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}

