// Copyright (c) 2025 渟雲. All rights reserved.
//
// Licensed under the TOSSRCU 2025.9 License (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//  https://raw.githubusercontent.com/M3351AN/M3351AN/9e7630a8511b8306c62952ca1a4f1ce0cc5b784a/LICENSE
//
// -----------------------------------------------------------------------------
// File: Program.cs
// Author: 渟雲(quq[at]outlook.it)
// Date: 2025-12-10
//
// -----------------------------------------------------------------------------
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using SPT.Fuyu.Patcher.Blazor;
using SPT.Fuyu.Patcher.Blazor.Services;
using System.Buffers;
using System.Diagnostics;

var builder = WebAssemblyHostBuilder.CreateDefault(args);

builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

builder.Services.AddScoped(sp =>
{
    var httpClient = new HttpClient
    {
        BaseAddress = new Uri(builder.HostEnvironment.BaseAddress)
    };

    return httpClient;
});

builder.Services.AddScoped<ExeAnalyzerService>();
builder.Services.AddScoped<JsInteropService>();

var host = builder.Build();

_ = Task.Run(async () =>
{
    await Task.Delay(500);
    await LightweightWarmupAsync(host);
});

await host.RunAsync();

static async Task LightweightWarmupAsync(WebAssemblyHost host)
{
    try
    {
        var stopwatch = Stopwatch.StartNew();

        var warmupTasks = new List<Task>
        {
            Task.Run(() => PreloadService<ExeAnalyzerService>(host)),
            Task.Run(() => PreloadService<JsInteropService>(host))
        };

        var dotnetWarmup = Task.Run(() =>
        {
            try
            {
                _ = new MemoryStream(64);
                _ = typeof(List<byte>);
                _ = typeof(Dictionary<string, object>);
                _ = ArrayPool<byte>.Shared.Rent(1);
                _ = BitConverter.ToString(new byte[] { 0x01 });
            }
            catch {
            }
        });

        warmupTasks.Add(dotnetWarmup);

        var combinedTask = Task.WhenAll(warmupTasks);
        var timeoutTask = Task.Delay(TimeSpan.FromMilliseconds(150));

        await Task.WhenAny(combinedTask, timeoutTask);

        stopwatch.Stop();
        Console.WriteLine($"Warmuped: {stopwatch.ElapsedMilliseconds}ms");
    }
    catch
    {
    }
}

static void PreloadService<T>(WebAssemblyHost host) where T : class
{
    try
    {
        var service = host.Services.GetService<T>();
        if (service != null)
        {
            if (service is ExeAnalyzerService analyzer)
            {
                _ = analyzer.GetType().GetProperty("ByteArrayPool")?.GetValue(null);
            }
        }
    }
    catch
    {
    }
}
