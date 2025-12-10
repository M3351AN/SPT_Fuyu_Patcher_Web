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
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;

namespace SPT.Fuyu.Patcher.Blazor.Services
{
    public class ExeAnalyzerService
    {
        public class AnalysisResult
        {
            public string FileName { get; set; } = string.Empty;
            public long FileSize { get; set; }
            public bool Success { get; set; }
            public string ErrorMessage { get; set; } = string.Empty;
            public List<string> Logs { get; set; } = new();
            public List<MZHeader> MzHeaders { get; set; } = new();
            public List<EmbeddedAssembly> EmbeddedAssemblies { get; set; } = new();
            public ValidateMethodInfo? ValidateMethod { get; set; }
            public List<PatternMatch> PatternMatches { get; set; } = new();
            public long PatchOffset { get; set; } = -1;
            public bool AlreadyPatched { get; set; }
            public byte[]? OriginalData { get; set; }
            public byte[]? ModifiedData { get; set; }
        }

        public class MZHeader
        {
            public long Offset { get; set; }
            public int PESize { get; set; }
        }

        public class EmbeddedAssembly
        {
            public long Offset { get; set; }
            public int Size { get; set; }
            public bool IsManaged { get; set; }
        }

        public class ValidateMethodInfo
        {
            public string Namespace { get; set; } = string.Empty;
            public string TypeName { get; set; } = string.Empty;
            public string MethodName { get; set; } = string.Empty;
            public int RVA { get; set; }
            public long StartOffsetInAssembly { get; set; }
            public long StartOffsetInFile { get; set; }
        }

        public class PatternMatch
        {
            public long Offset { get; set; }
            public byte[] Pattern { get; set; } = Array.Empty<byte>();
            public string PatternType { get; set; } = string.Empty;
            public byte[] Context { get; set; } = Array.Empty<byte>();
            public string HexString => BitConverter.ToString(Pattern).Replace("-", " ");
            public string OffsetHex => $"0x{Offset:X8}";
        }

        public async Task<AnalysisResult> AnalyzeFileAsync(Stream fileStream, string fileName)
        {
            var result = new AnalysisResult
            {
                FileName = fileName,
                Success = false
            };

            try
            {
                using var memoryStream = new MemoryStream();
                await fileStream.CopyToAsync(memoryStream);
                var exeData = memoryStream.ToArray();
                result.OriginalData = exeData;
                result.FileSize = exeData.Length;

                result.MzHeaders = FindMZHeaders(exeData);

                bool foundValidateMethod = false;

                foreach (var mzHeader in result.MzHeaders)
                {
                    if (IsManagedAssembly(exeData, (int)mzHeader.Offset))
                    {
                        var assemblyInfo = new EmbeddedAssembly
                        {
                            Offset = mzHeader.Offset,
                            Size = mzHeader.PESize,
                            IsManaged = true
                        };
                        result.EmbeddedAssemblies.Add(assemblyInfo);

                        using var ms = new MemoryStream(exeData, (int)mzHeader.Offset, mzHeader.PESize);
                        using var peReader = new PEReader(ms);

                        if (peReader.HasMetadata)
                        {
                            var metadataReader = peReader.GetMetadataReader();

                            foreach (var typeDefHandle in metadataReader.TypeDefinitions)
                            {
                                var typeDef = metadataReader.GetTypeDefinition(typeDefHandle);
                                string typeName = metadataReader.GetString(typeDef.Name);
                                string typeNamespace = metadataReader.GetString(typeDef.Namespace);

                                if (typeName == "ValidationUtil" && typeNamespace == "SPT.Launcher.Helpers")
                                {
                                    foreach (var methodHandle in typeDef.GetMethods())
                                    {
                                        var methodDef = metadataReader.GetMethodDefinition(methodHandle);
                                        string methodName = metadataReader.GetString(methodDef.Name);

                                        if (methodName == "Validate")
                                        {
                                            int rva = methodDef.RelativeVirtualAddress;
                                            if (rva == 0) continue;

                                            long methodOffsetInAssembly = RvaToFileOffset(peReader, rva);
                                            if (methodOffsetInAssembly < 0) continue;

                                            long absoluteOffset = mzHeader.Offset + methodOffsetInAssembly;

                                            var validateMethod = new ValidateMethodInfo
                                            {
                                                Namespace = typeNamespace,
                                                TypeName = typeName,
                                                MethodName = methodName,
                                                RVA = rva,
                                                StartOffsetInAssembly = methodOffsetInAssembly,
                                                StartOffsetInFile = absoluteOffset
                                            };
                                            result.ValidateMethod = validateMethod;

                                            var patterns = SearchPatternsNearMethod(exeData, absoluteOffset, result);
                                            result.PatternMatches = patterns;

                                            foundValidateMethod = true;
                                            break;
                                        }
                                    }

                                    if (foundValidateMethod) break;
                                }
                            }
                        }
                    }

                    if (foundValidateMethod) break;
                }

                if (!foundValidateMethod)
                {
                    result.ErrorMessage = "Unfound Validate() Method";
                    result.Logs.Add("Unfound Validate() Method");
                }
                else
                {
                    result.Success = true;
                }
            }
            catch (Exception ex)
            {
                result.ErrorMessage = ex.Message;
                result.Logs.Add($"Error: {ex.Message}");
            }

            return result;
        }

        private List<MZHeader> FindMZHeaders(byte[] data)
        {
            var headers = new List<MZHeader>();

            for (int i = 0; i < data.Length - 64; i++)
            {
                if (data[i] == 0x4D && data[i + 1] == 0x5A)
                {
                    int peSize = GetPESize(data, i);
                    if (peSize > 1024)
                    {
                        headers.Add(new MZHeader
                        {
                            Offset = i,
                            PESize = peSize
                        });
                    }
                }
            }

            return headers;
        }

        private int GetPESize(byte[] data, int start)
        {
            try
            {
                int peOffset = BitConverter.ToInt32(data, start + 0x3C);
                if (start + peOffset + 6 >= data.Length) return 0;

                ushort numSections = BitConverter.ToUInt16(data, start + peOffset + 6);
                ushort optionalHeaderSize = BitConverter.ToUInt16(data, start + peOffset + 20);
                int sectionTableOffset = start + peOffset + 24 + optionalHeaderSize;

                int maxSize = 0;
                for (int i = 0; i < numSections; i++)
                {
                    int sectionOffset = sectionTableOffset + i * 40;
                    if (sectionOffset + 40 > data.Length) break;

                    int rawSize = BitConverter.ToInt32(data, sectionOffset + 16);
                    int rawAddr = BitConverter.ToInt32(data, sectionOffset + 20);

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

        private bool IsManagedAssembly(byte[] data, int start)
        {
            try
            {
                int peOffset = BitConverter.ToInt32(data, start + 0x3C);
                if (peOffset + 4 > data.Length) return false;
                uint peSignature = BitConverter.ToUInt32(data, start + peOffset);
                if (peSignature != 0x00004550) return false;

                int dataDirOffset = start + peOffset + 24 + 0x60 + 8;
                if (dataDirOffset + 8 > data.Length) return false;

                int cliRva = BitConverter.ToInt32(data, dataDirOffset);
                int cliSize = BitConverter.ToInt32(data, dataDirOffset + 4);

                return cliRva != 0 && cliSize > 0;
            }
            catch
            {
                return false;
            }
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

        private List<PatternMatch> SearchPatternsNearMethod(byte[] exeData, long methodStart, AnalysisResult result)
        {
            var matches = new List<PatternMatch>();

            int searchStart = (int)methodStart;
            int searchEnd = Math.Min(exeData.Length - 4, searchStart + 2000);

            for (int i = searchStart; i <= searchEnd; i++)
            {
                if (exeData[i] == 0x16 && exeData[i + 1] == 0xFE &&
                    exeData[i + 2] == 0x01 && exeData[i + 3] == 0x2A)
                {
                    var match = new PatternMatch
                    {
                        Offset = i,
                        Pattern = new byte[] { 0x16, 0xFE, 0x01, 0x2A },
                        PatternType = "Unpatched",
                        Context = GetContextBytes(exeData, i, 32)
                    };
                    matches.Add(match);
                    result.PatchOffset = i;
                }
            }

            for (int i = searchStart; i <= searchEnd; i++)
            {
                if (exeData[i] == 0x25 && exeData[i + 1] == 0xFE &&
                    exeData[i + 2] == 0x01 && exeData[i + 3] == 0x2A)
                {
                    var match = new PatternMatch
                    {
                        Offset = i,
                        Pattern = new byte[] { 0x25, 0xFE, 0x01, 0x2A },
                        PatternType = "Patched",
                        Context = GetContextBytes(exeData, i, 32)
                    };
                    matches.Add(match);
                    result.AlreadyPatched = true;
                }
            }

            if (matches.Count == 0)
            {
                for (int i = searchStart; i <= searchEnd - 3; i++)
                {
                    if (exeData[i] == 0x16 && exeData[i + 1] == 0xFE && exeData[i + 3] == 0x2A)
                    {
                        var match = new PatternMatch
                        {
                            Offset = i,
                            Pattern = new byte[] { exeData[i], exeData[i + 1], exeData[i + 2], exeData[i + 3] },
                            PatternType = $"Variant_{exeData[i + 2]:X2}",
                            Context = GetContextBytes(exeData, i, 32)
                        };
                        matches.Add(match);
                    }
                }
            }

            return matches.OrderBy(m => m.Offset).ToList();
        }

        private byte[] GetContextBytes(byte[] data, int offset, int contextSize)
        {
            int start = Math.Max(0, offset - contextSize / 2);
            int end = Math.Min(data.Length, offset + contextSize / 2);

            var context = new byte[end - start];
            Array.Copy(data, start, context, 0, context.Length);

            return context;
        }

        public async Task<byte[]> ApplyPatchAsync(AnalysisResult result)
        {
            if (result.OriginalData == null || result.PatchOffset < 0)
                throw new InvalidOperationException("Patch Error");

            return await ApplyPatchAsync(result.OriginalData, result.PatchOffset);
        }

        public async Task<byte[]> ApplyPatchAsync(byte[] originalData, long patchOffset)
        {
            var modifiedData = new byte[originalData.Length];
            Array.Copy(originalData, modifiedData, originalData.Length);

            if (patchOffset >= 0 && patchOffset + 3 < modifiedData.Length)
            {
                modifiedData[patchOffset] = 0x25;
            }

            return await Task.FromResult(modifiedData);
        }
    }
}
