// Copyright (c) 2025 渟雲. All rights reserved.
//
// Licensed under the TOSSRCU 2025.9 License (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//  https://raw.githubusercontent.com/M3351AN/M3351AN/9e7630a8511b8306c62952ca1a4f1ce0cc5b784a/LICENSE
//
// -----------------------------------------------------------------------------
// File: ExeAnalyzerService.cs
// Author: 渟雲(quq[at]outlook.it)
// Date: 2025-12-10
//
// -----------------------------------------------------------------------------
using System.Buffers;
using System.Collections.Concurrent;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;

namespace SPT.Fuyu.Patcher.Blazor.Services
{
    public class ExeAnalyzerService
    {

        private static readonly ArrayPool<byte> ByteArrayPool = ArrayPool<byte>.Shared;

        public class AnalysisResult
        {
            public string FileName { get; init; } = string.Empty;
            public long FileSize { get; set; }
            public bool Success { get; set; }
            public string ErrorMessage { get; set; } = string.Empty;
            public List<string> Logs { get; } = new();
            public List<MZHeader> MzHeaders { get; } = new();
            public List<EmbeddedAssembly> EmbeddedAssemblies { get; } = new();
            public ValidateMethodInfo? ValidateMethod { get; set; }
            public List<PatternMatch> PatternMatches { get; } = new();
            public long PatchOffset { get; set; } = -1;
            public bool AlreadyPatched { get; set; }
            public byte[]? OriginalData { get; set; }
        }

        public record MZHeader(long Offset, int PESize);

        public record EmbeddedAssembly(long Offset, int Size, bool IsManaged);

        public record ValidateMethodInfo(
            string Namespace,
            string TypeName,
            string MethodName,
            int RVA,
            long StartOffsetInAssembly,
            long StartOffsetInFile
        );

        public record PatternMatch(
            long Offset,
            byte[] Pattern,
            string PatternType,
            byte[] Context
        )
        {
            public string HexString => BitConverter.ToString(Pattern).Replace("-", " ");
            public string OffsetHex => $"0x{Offset:X8}";
        }

        public async Task<AnalysisResult> AnalyzeFileAsync(
            Stream fileStream,
            string fileName,
            IProgress<int>? progress = null,
            CancellationToken cancellationToken = default)
        {
            var result = new AnalysisResult
            {
                FileName = fileName,
                Success = false
            };

            try
            {
                progress?.Report(10);
                byte[] exeData = await ReadStreamToPooledArrayAsync(fileStream, cancellationToken);
                result.OriginalData = exeData;
                result.FileSize = exeData.Length;

                progress?.Report(20);
                result.MzHeaders.AddRange(FindMZHeaders(exeData));
                result.Logs.Add($"Found {result.MzHeaders.Count} MZ headers");

                if (result.MzHeaders.Count == 0)
                {
                    result.ErrorMessage = "No valid MZ header";
                    return result;
                }

                progress?.Report(30);
                var validateMethods = await FindValidateMethodsParallelAsync(
                    exeData,
                    result.MzHeaders,
                    cancellationToken);

                var firstMethod = validateMethods.FirstOrDefault();
                if (firstMethod != null)
                {
                    result.ValidateMethod = firstMethod;
                    result.EmbeddedAssemblies.AddRange(validateMethods
                        .Select(m => new EmbeddedAssembly(
                            Offset: m.StartOffsetInFile - m.StartOffsetInAssembly,
                            Size: result.MzHeaders.First(h => h.Offset == m.StartOffsetInFile - m.StartOffsetInAssembly).PESize,
                            IsManaged: true)));

                    progress?.Report(70);
                    var patterns = SearchPatternsNearMethod(
                        exeData,
                        firstMethod.StartOffsetInFile,
                        result);
                    result.PatternMatches.AddRange(patterns);

                    var unpatched = patterns.FirstOrDefault(p => p.PatternType == "Unpatched");
                    if (unpatched != null)
                    {
                        result.PatchOffset = unpatched.Offset;
                    }
                    result.AlreadyPatched = patterns.Any(p => p.PatternType == "Patched");

                    result.Success = true;
                    result.Logs.Add($"Found method: {firstMethod.Namespace}.{firstMethod.TypeName}.{firstMethod.MethodName}");
                }
                else
                {
                    result.ErrorMessage = "Unfound Validate() method";
                    result.Logs.Add("Unfound Validate() method");
                }

                progress?.Report(100);
            }
            catch (OperationCanceledException)
            {
                result.ErrorMessage = "operation cancel";
                result.Logs.Add("operation cancel");
            }
            catch (Exception ex)
            {
                result.ErrorMessage = ex.Message;
                result.Logs.Add($"parser error: {ex.Message}");
            }

            return result;
        }

        private async Task<byte[]> ReadStreamToPooledArrayAsync(Stream stream, CancellationToken cancellationToken)
        {
            if (stream is MemoryStream ms)
                return ms.ToArray();

            long length = stream.Length;
            if (length > int.MaxValue)
                throw new InvalidOperationException("too large the file");

            byte[] rented = ByteArrayPool.Rent((int)length);
            try
            {
                int totalRead = 0;
                while (totalRead < length)
                {
                    int read = await stream.ReadAsync(
                        rented.AsMemory(totalRead, (int)length - totalRead),
                        cancellationToken);
                    if (read == 0) break;
                    totalRead += read;
                }

                byte[] result = new byte[totalRead];
                Array.Copy(rented, 0, result, 0, totalRead);
                return result;
            }
            finally
            {
                ByteArrayPool.Return(rented);
            }
        }

        private List<MZHeader> FindMZHeaders(byte[] data)
        {
            var headers = new List<MZHeader>();
            ReadOnlySpan<byte> span = data;

            for (int i = 0; i <= span.Length - 64; i++)
            {
                if (span[i] == 0x4D && span[i + 1] == 0x5A) // 'MZ'
                {
                    int peSize = GetPESize(span, i);
                    if (peSize > 1024 && i + peSize <= data.Length)
                    {
                        headers.Add(new MZHeader(i, peSize));
                    }
                }
            }

            return headers;
        }

        private int GetPESize(ReadOnlySpan<byte> data, int start)
        {
            try
            {
                int peOffset = BitConverter.ToInt32(data.Slice(start + 0x3C, 4).ToArray(), 0);
                if (start + peOffset + 6 >= data.Length) return 0;

                ushort numSections = BitConverter.ToUInt16(data.Slice(start + peOffset + 6, 2).ToArray(), 0);
                ushort optionalHeaderSize = BitConverter.ToUInt16(data.Slice(start + peOffset + 20, 2).ToArray(), 0);
                int sectionTableOffset = start + peOffset + 24 + optionalHeaderSize;

                int maxSize = 0;
                for (int i = 0; i < numSections; i++)
                {
                    int sectionOffset = sectionTableOffset + i * 40;
                    if (sectionOffset + 40 > data.Length) break;

                    int rawSize = BitConverter.ToInt32(data.Slice(sectionOffset + 16, 4).ToArray(), 0);
                    int rawAddr = BitConverter.ToInt32(data.Slice(sectionOffset + 20, 4).ToArray(), 0);

                    int sectionEnd = rawAddr + rawSize;
                    if (sectionEnd > maxSize)
                        maxSize = sectionEnd;
                }

                return maxSize;
            }
            catch
            {
                return 0;
            }
        }

        private async Task<List<ValidateMethodInfo>> FindValidateMethodsParallelAsync(
            byte[] exeData,
            List<MZHeader> mzHeaders,
            CancellationToken cancellationToken)
        {
            var results = new ConcurrentBag<ValidateMethodInfo>();

            // Parallel.ForEachAsync
            var parallelOptions = new ParallelOptions
            {
                MaxDegreeOfParallelism = Environment.ProcessorCount,
                CancellationToken = cancellationToken
            };

            await Parallel.ForEachAsync(mzHeaders, parallelOptions, async (mzHeader, ct) =>
            {
                if (!IsManagedAssembly(exeData, (int)mzHeader.Offset))
                    return;

                var method = await Task.Run(() =>
                    FindValidateMethodInAssembly(exeData, mzHeader), ct);

                if (method != null)
                {
                    results.Add(method);
                }
            });

            return results.ToList();
        }

        private bool IsManagedAssembly(byte[] data, int start)
        {
            try
            {
                if (start + 0x3C + 4 > data.Length) return false;

                int peOffset = System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(
                    data.AsSpan(start + 0x3C, 4));

                if (start + peOffset + 24 + 0x60 + 8 > data.Length) return false;

                uint peSignature = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(
                    data.AsSpan(start + peOffset, 4));
                if (peSignature != 0x00004550) return false;

                int cliDirOffset = start + peOffset + 24 + 0x60 + 8;
                int cliRva = System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(
                    data.AsSpan(cliDirOffset, 4));
                int cliSize = System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(
                    data.AsSpan(cliDirOffset + 4, 4));

                return cliRva != 0 && cliSize > 0;
            }
            catch
            {
                return false;
            }
        }

        private ValidateMethodInfo? FindValidateMethodInAssembly(byte[] exeData, MZHeader mzHeader)
        {
            try
            {
                using var ms = new MemoryStream(
                    exeData,
                    (int)mzHeader.Offset,
                    mzHeader.PESize);
                using var peReader = new PEReader(ms);

                if (!peReader.HasMetadata)
                    return null;

                var metadataReader = peReader.GetMetadataReader();

                const string targetTypeName = "ValidationUtil";
                const string targetNamespace = "SPT.Launcher.Helpers";
                const string targetMethodName = "Validate";

                foreach (var typeDefHandle in metadataReader.TypeDefinitions)
                {
                    var typeDef = metadataReader.GetTypeDefinition(typeDefHandle);

                    if (!metadataReader.StringComparer.Equals(typeDef.Name, targetTypeName) ||
                        !metadataReader.StringComparer.Equals(typeDef.Namespace, targetNamespace))
                        continue;

                    foreach (var methodHandle in typeDef.GetMethods())
                    {
                        var methodDef = metadataReader.GetMethodDefinition(methodHandle);

                        if (metadataReader.StringComparer.Equals(methodDef.Name, targetMethodName))
                        {
                            int rva = methodDef.RelativeVirtualAddress;
                            if (rva == 0) continue;

                            long methodOffsetInAssembly = RvaToFileOffset(peReader, rva);
                            if (methodOffsetInAssembly < 0) continue;

                            long absoluteOffset = mzHeader.Offset + methodOffsetInAssembly;

                            return new ValidateMethodInfo(
                                Namespace: targetNamespace,
                                TypeName: targetTypeName,
                                MethodName: targetMethodName,
                                RVA: rva,
                                StartOffsetInAssembly: methodOffsetInAssembly,
                                StartOffsetInFile: absoluteOffset
                            );
                        }
                    }
                }
            }
            catch
            {
            }

            return null;
        }

        private long RvaToFileOffset(PEReader peReader, int rva)
        {
            var sectionHeaders = peReader.PEHeaders.SectionHeaders;

            foreach (var section in sectionHeaders)
            {
                uint sectionRva = (uint)section.VirtualAddress;
                uint sectionSize = (uint)section.VirtualSize;

                if (rva >= sectionRva && rva < sectionRva + sectionSize)
                {
                    return rva - sectionRva + section.PointerToRawData;
                }
            }

            return -1;
        }

        private List<PatternMatch> SearchPatternsNearMethod(
            byte[] exeData,
            long methodStart,
            AnalysisResult result)
        {
            var matches = new List<PatternMatch>();
            ReadOnlySpan<byte> dataSpan = exeData;

            int searchStart = Math.Max(0, (int)methodStart - 500);
            int searchEnd = Math.Min(exeData.Length - 4, (int)methodStart + 1500);

            var searchPatterns = new (byte[] Pattern, string Type)[]
            {
                (new byte[] { 0x16, 0xFE, 0x01, 0x2A }, "Unpatched"),
                (new byte[] { 0x25, 0xFE, 0x01, 0x2A }, "Patched")
            };

            ReadOnlySpan<byte> searchArea = dataSpan.Slice(searchStart, searchEnd - searchStart);

            foreach (var (pattern, patternType) in searchPatterns)
            {
                int index = 0;
                while (index <= searchArea.Length - pattern.Length)
                {
                    if (searchArea.Slice(index, pattern.Length).SequenceEqual(pattern))
                    {
                        int absoluteOffset = searchStart + index;

                        matches.Add(new PatternMatch(
                            Offset: absoluteOffset,
                            Pattern: pattern,
                            PatternType: patternType,
                            Context: GetContextBytes(exeData, absoluteOffset, 64)
                        ));

                        index += pattern.Length;
                    }
                    else
                    {
                        index++;
                    }
                }
            }

            if (matches.Count == 0)
            {
                SearchVariantPatterns(exeData, searchStart, searchArea, matches);
            }

            return matches.OrderBy(m => m.Offset).ToList();
        }

        private void SearchVariantPatterns(
            byte[] exeData,
            int searchStart,
            ReadOnlySpan<byte> searchArea,
            List<PatternMatch> matches)
        {
            for (int i = 0; i <= searchArea.Length - 4; i++)
            {
                if (searchArea[i] == 0x16 &&
                    searchArea[i + 1] == 0xFE &&
                    searchArea[i + 3] == 0x2A)
                {
                    int absoluteOffset = searchStart + i;
                    var pattern = new byte[] {
                        searchArea[i],
                        searchArea[i + 1],
                        searchArea[i + 2],
                        searchArea[i + 3]
                    };

                    matches.Add(new PatternMatch(
                        Offset: absoluteOffset,
                        Pattern: pattern,
                        PatternType: $"Variant_{searchArea[i + 2]:X2}",
                        Context: GetContextBytes(exeData, absoluteOffset, 64)
                    ));
                }
            }
        }

        private byte[] GetContextBytes(byte[] data, int offset, int contextSize)
        {
            int start = Math.Max(0, offset - contextSize / 2);
            int length = Math.Min(data.Length - start, contextSize);

            return data.AsSpan(start, length).ToArray();
        }

        public async Task<byte[]> ApplyPatchAsync(
            AnalysisResult result,
            CancellationToken cancellationToken = default)
        {
            if (result.OriginalData == null || result.PatchOffset < 0)
                throw new InvalidOperationException("Offset error!");

            return await ApplyPatchAsync(
                result.OriginalData,
                result.PatchOffset,
                cancellationToken);
        }

        public async Task<byte[]> ApplyPatchAsync(
            byte[] originalData,
            long patchOffset,
            CancellationToken cancellationToken = default)
        {
            byte[] rented = ByteArrayPool.Rent(originalData.Length);

            try
            {
                Array.Copy(originalData, 0, rented, 0, originalData.Length);

                if (patchOffset >= 0 && patchOffset < originalData.Length)
                {
                    rented[patchOffset] = 0x25;
                }

                byte[] result = new byte[originalData.Length];
                Array.Copy(rented, 0, result, 0, originalData.Length);

                return await Task.FromResult(result);
            }
            finally
            {
                ByteArrayPool.Return(rented);
            }
        }
    }
}
