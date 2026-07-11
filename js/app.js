// Copyright (c) 2025 渟雲. All rights reserved.
//
// Licensed under the TOSSRCU 2025.9 License (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//  https://raw.githubusercontent.com/M3351AN/M3351AN/9e7630a8511b8306c62952ca1a4f1ce0cc5b784a/LICENSE
//
// -----------------------------------------------------------------------------
// File: app.js
// Author: 渟雲(quq[at]outlook.it)
// Date: 2026-07-11
//
// -----------------------------------------------------------------------------
// UI controller: loads the WASM patcher, wires up file selection / drag-drop,
// drives the patch flow, and triggers the patched-file download. Shared by
// index.html (full page) and iframe.html (embedded variant) — elements that
// don't exist in the iframe are simply skipped.
// ----------------------------------------------------------------------------

import init, { patch_file } from '../pkg/spt_fuyu_patcher_web.js';
import { getText } from './i18n.js';

const MAX_FILE_SIZE = 100 * 1024 * 1024;

const state = {
    lang: 'zh',
    selectedFile: null,
    isProcessing: false,
    wasmReady: false
};

const $ = (id) => document.getElementById(id);

async function main() {
    detectLanguage();
    applyLanguage();

    try {
        await init(new URL('../pkg/spt_fuyu_patcher_web_bg.wasm', import.meta.url));
        state.wasmReady = true;
    } catch (err) {
        console.error('WASM init failed:', err);
        showStatus(getText(state.lang, 'unknownError') + ': ' + err, 'error');
    }

    hideLoadingMask();
    wireEvents();
    render();
}

function detectLanguage() {
    const browserLang = (navigator.language || navigator.userLanguage || '').toLowerCase();
    state.lang = browserLang.startsWith('zh') ? 'zh' : 'en';
}

function applyLanguage() {
    document.documentElement.lang = state.lang === 'zh' ? 'zh-CN' : 'en';
}

function render() {
    const t = (key) => getText(state.lang, key);
    setText('langToggle', t('langToggle'));
    setText('title', t('title'));
    setText('subtitle', t('subtitle'));
    setText('uploadText', t('uploadText'));
    setText('fileSupport', t('fileSupport'));
    setText('patchButton', t('patchButton'));
    setText('advantagesTitle', t('advantagesTitle'));
    setText('feature1Title', t('feature1Title'));
    setText('feature1Desc', t('feature1Desc'));
    setText('feature2Title', t('feature2Title'));
    setText('feature2Desc', t('feature2Desc'));
    setText('feature3Title', t('feature3Title'));
    setText('feature3Desc', t('feature3Desc'));
    setText('feature4Title', t('feature4Title'));
    setText('feature4Desc', t('feature4Desc'));
    setText('sponsorTitle', t('sponsorTitle'));
    setText('sponsorText', t('sponsorText'));
    setText('sponsorButton', t('sponsorButton'));
    const sponsorHint = $('sponsorHint');
    if (sponsorHint) sponsorHint.innerHTML = t('sponsorHint');
    renderFileInfo();
    renderPatchButton();
}

function renderFileInfo() {
    const el = $('fileInfo');
    if (!el) return;
    if (state.selectedFile) {
        const sizeKb = Math.round(state.selectedFile.size / 1024);
        el.textContent = `${getText(state.lang, 'fileSelected')}: ${state.selectedFile.name} (${sizeKb} KB)`;
        el.style.display = '';
    } else {
        el.style.display = 'none';
    }
}

function renderPatchButton() {
    const btn = $('patchButton');
    if (!btn) return;
    btn.disabled = !state.selectedFile || state.isProcessing || !state.wasmReady;
}

function wireEvents() {
    const uploadArea = $('uploadArea');
    const fileInput = $('fileInput');
    const patchButton = $('patchButton');
    const langToggle = $('langToggle');

    if (uploadArea) {
        uploadArea.addEventListener('click', () => fileInput && fileInput.click());
    }
    if (fileInput) {
        fileInput.addEventListener('change', (e) => onFileSelected(e.target.files[0]));
    }
    if (patchButton) {
        patchButton.addEventListener('click', startPatch);
    }
    if (langToggle) {
        langToggle.addEventListener('click', toggleLanguage);
    }

    // Drag & drop onto the whole document redirects to the file input.
    ['dragover', 'drop', 'dragenter', 'dragleave'].forEach((evt) => {
        document.addEventListener(evt, (e) => {
            e.preventDefault();
            e.stopPropagation();
        }, { passive: false });
    });
    document.addEventListener('drop', (e) => {
        const files = e.dataTransfer && e.dataTransfer.files;
        if (files && files.length > 0 && fileInput) {
            const dt = new DataTransfer();
            Array.from(files).forEach((f) => dt.items.add(f));
            fileInput.files = dt.files;
            fileInput.dispatchEvent(new Event('change', { bubbles: true }));
        }
    }, { passive: false });
}

function toggleLanguage() {
    state.lang = state.lang === 'zh' ? 'en' : 'zh';
    applyLanguage();
    render();
}

function onFileSelected(file) {
    hideStatus();
    if (!file) return;

    if (file.size > MAX_FILE_SIZE) {
        alert(getText(state.lang, 'fileTooLarge'));
        state.selectedFile = null;
        renderFileInfo();
        renderPatchButton();
        return;
    }
    if (!file.name.toLowerCase().endsWith('.exe')) {
        alert(getText(state.lang, 'notExe'));
        state.selectedFile = null;
        renderFileInfo();
        renderPatchButton();
        return;
    }

    state.selectedFile = file;
    renderFileInfo();
    renderPatchButton();
}

async function startPatch() {
    if (!state.selectedFile || state.isProcessing || !state.wasmReady) return;

    state.isProcessing = true;
    setProgress(0, '');
    hideStatus();
    renderPatchButton();

    try {
        const bytes = new Uint8Array(await state.selectedFile.arrayBuffer());
        const onProgress = (percent, phase) => setProgress(percent, getText(state.lang, phase));
        const result = await patch_file(bytes, state.selectedFile.name, onProgress);

        if (result.success) {
            if (result.patched_data) {
                downloadBytes(result.patched_data, result.output_filename);
            }
            showStatus(getText(state.lang, 'success'), 'success');
            setTimeout(resetState, 2000);
        } else {
            const message = result.error_code
                ? getText(state.lang, result.error_code)
                : getText(state.lang, 'unknownError');
            showStatus(message, 'error');
        }
    } catch (err) {
        console.error('Patch failed:', err);
        showStatus(getText(state.lang, 'unknownError') + ': ' + err, 'error');
    } finally {
        state.isProcessing = false;
        renderPatchButton();
    }
}

function setProgress(percent, message) {
    const container = $('progressContainer');
    const bar = $('progressBar');
    const pct = $('progressPct');
    const text = $('progressText');
    if (container) container.style.display = '';
    if (bar) bar.style.width = percent + '%';
    if (pct) pct.textContent = percent + '%';
    if (text) text.textContent = message;
}

function showStatus(message, cls) {
    const el = $('status');
    if (!el) return;
    el.textContent = message;
    el.className = 'status ' + cls;
    el.style.display = '';
}

function hideStatus() {
    const el = $('status');
    if (el) el.style.display = 'none';
}

function resetState() {
    state.selectedFile = null;
    state.isProcessing = false;
    const container = $('progressContainer');
    if (container) container.style.display = 'none';
    hideStatus();
    const fileInput = $('fileInput');
    if (fileInput) fileInput.value = '';
    renderFileInfo();
    renderPatchButton();
}

function downloadBytes(bytes, filename) {
    const blob = new Blob([bytes], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function setText(id, text) {
    const el = $(id);
    if (el) el.textContent = text;
}

function hideLoadingMask() {
    const mask = $('loading-mask');
    if (!mask) return;
    mask.classList.add('hidden');
    mask.addEventListener('transitionend', () => mask.remove(), { once: true });
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', main);
} else {
    main();
}
