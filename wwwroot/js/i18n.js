// Copyright (c) 2025 渟雲. All rights reserved.
//
// Licensed under the TOSSRCU 2025.9 License (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//  https://raw.githubusercontent.com/M3351AN/M3351AN/9e7630a8511b8306c62952ca1a4f1ce0cc5b784a/LICENSE
//
// -----------------------------------------------------------------------------
// File: i18n.js
// Author: 渟雲(quq[at]outlook.it)
// Date: 2026-07-11
//
// -----------------------------------------------------------------------------
// Localization tables for zh/en. Keys cover UI strings, progress phases, and
// the error codes returned by the WASM patcher.
// -----------------------------------------------------------------------------

export const messages = {
    zh: {
        title: 'SPT Fuyu 在线修补器',
        subtitle: '在线修补SPT启动器 绕过正版验证',
        uploadText: '选择或拖放启动器可执行文件到此处',
        fileSupport: '例如 SPT.Launcher.exe',
        fileSelected: '已选择文件',
        patchButton: '修补文件',
        advantagesTitle: '我们的优势',
        feature1Title: '纯前端实现',
        feature1Desc: '所有处理都在您的浏览器中完成 - 无需上传到服务器，没有外部依赖。',
        feature2Title: '无残留文件',
        feature2Desc: '我们的解决方案在修补完成后不会在您的电脑中留下任何多余文件。',
        feature3Title: '无需注册表权限',
        feature3Desc: '我们不需要危险的权限去修改您的系统注册表或进行系统更改。',
        feature4Title: '无需下载任何工具',
        feature4Desc: '直接在浏览器中使用，无需安装或下载任何额外软件。',
        langToggle: 'EN',
        selectFile: '请选择文件',
        success: '修补成功',
        unknownError: '未知错误',
        notFound: '未找到目标字节序列',
        alreadyPatched: '文件已经修补过',
        notExe: '请选择一个有效的EXE文件',
        fileTooLarge: '文件过大！请选择小于 100MB 的文件。',
        sponsorTitle: '需要您的支持',
        sponsorText: '由于域名注册局将 tkm.icu 设为 Premier 域名，年费已翻了五倍。如此下去将无法正常维持服务的运行。如果您觉得这个工具有用，希望得到您的赞助支持。',
        sponsorButton: '前往爱发电赞助',
        sponsorHint: '服务器的域名年费翻了五倍，如果这个工具帮到了您，欢迎<a href="https://afdian.com/a/M3351AN" target="_blank" rel="noopener">赞助支持</a>',
        // progress phases
        reading: '正在读取文件...',
        analyzing: '正在分析文件...',
        patching: '正在应用修补...',
        preparing: '正在准备下载...',
        done: '下载已开始！',
        // error codes from WASM
        no_mz: '无有效 MZ 头',
        no_validate: '未找到 Validate() 方法'
    },
    en: {
        title: 'SPT Fuyu Patcher Online',
        subtitle: 'bypass EFT live install validate of SPT launcher',
        uploadText: 'Select or drag & drop launcher executable file here',
        fileSupport: 'i.e., SPT.Launcher.exe',
        fileSelected: 'File selected',
        patchButton: 'Patch File',
        advantagesTitle: 'Our Advantages',
        feature1Title: 'Pure Frontend Solution',
        feature1Desc: 'All processing happens in your browser - no server uploads, no external dependencies.',
        feature2Title: 'No Residual Files',
        feature2Desc: 'Our solution leaves no extra files on your computer after patching is complete.',
        feature3Title: 'No Registry Permissions Needed',
        feature3Desc: 'We don\'t require dangerous permissions to modify your system registry or make system changes.',
        feature4Title: 'No Tools to Download',
        feature4Desc: 'No need to install any additional software or tools, just open the webpage and use it.',
        langToggle: '中文',
        selectFile: 'Please select a file',
        success: 'Patch successful',
        unknownError: 'Unknown error',
        notFound: 'Target byte sequence not found',
        alreadyPatched: 'File already patched',
        notExe: 'Please select a valid EXE file',
        fileTooLarge: 'File too large! Please select a file less than 100MB.',
        sponsorTitle: 'Need Your Support',
        sponsorText: 'The domain registry has classified tkm.icu as a Premier domain, causing the annual fee to increase fivefold. Without support, we will be unable to keep this service running. If you find this tool useful, please consider sponsoring us.',
        sponsorButton: 'Sponsor on Afdian',
        sponsorHint: 'Our domain fee has increased fivefold. If this tool helped you, please consider <a href="https://afdian.com/a/M3351AN" target="_blank" rel="noopener">supporting us</a>.',
        reading: 'Reading file...',
        analyzing: 'Analyzing file...',
        patching: 'Applying patch...',
        preparing: 'Preparing download...',
        done: 'Download started!',
        no_mz: 'No valid MZ header',
        no_validate: 'Validate() method not found'
    }
};

export function getText(lang, key) {
    return (messages[lang] && messages[lang][key]) || key;
}
