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
// Date: 2025-1-22
//
// -----------------------------------------------------------------------------
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using SPT.Fuyu.Patcher.Blazor;
using SPT.Fuyu.Patcher.Blazor.Services;
using System.Diagnostics;
using System.Net.Http.Headers;

var builder = WebAssemblyHostBuilder.CreateDefault(args);

builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

builder.Services.AddSingleton(sp =>
{
    var httpClient = new HttpClient
    {
        BaseAddress = new Uri(builder.HostEnvironment.BaseAddress),
        Timeout = TimeSpan.FromSeconds(15)
    };

    httpClient.DefaultRequestHeaders.AcceptEncoding.Add(new StringWithQualityHeaderValue("br"));
    httpClient.DefaultRequestHeaders.AcceptEncoding.Add(new StringWithQualityHeaderValue("gzip"));

    return httpClient;
});

builder.Services.AddScoped<ExeAnalyzerService>();
builder.Services.AddScoped<JsInteropService>();

var host = builder.Build();

_ = LightweightWarmupAsync(host);

await host.RunAsync();

static async Task LightweightWarmupAsync(WebAssemblyHost host)
{
    var stopwatch = Stopwatch.StartNew();
    try
    {
        await Task.WhenAll(
            Task.Run(() => PreloadService<ExeAnalyzerService>(host)),
            Task.Run(() => PreloadService<JsInteropService>(host))
        );
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Warmup warning: {ex.Message}");
    }
    finally
    {
        stopwatch.Stop();
        Console.WriteLine($"Warmup completed: {stopwatch.ElapsedMilliseconds}ms");
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
