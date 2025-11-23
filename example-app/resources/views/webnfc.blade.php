@extends('layouts.app')

@section('title', 'SDM Backend Server Example')

@section('content')
    <h1 class="mb-4">Secure Dynamic Messaging Backend Server Example</h1>

    @if(config('sdm.demo_mode'))
        <div class="mb-4">
            <p>
                This page demonstrates the WebNFC functionality. WebNFC is supported in Chrome for Android (release 89 and later).
                <strong>Note:</strong> WebNFC requires HTTPS.
            </p>

            <button id="scanBtn" class="btn btn-primary mb-3">Scan NFC Tag</button>

            <div id="result" class="card d-none">
                <div class="card-body">
                    <h5 class="card-title">Scan Result</h5>
                    <div id="resultContent"></div>
                </div>
            </div>
        </div>

        <div class="mt-4">
            <a href="/" class="btn btn-secondary">Back</a>
        </div>
    @else
        <div class="alert alert-warning">
            This feature is disabled.
        </div>
    @endif
@endsection

@if(config('sdm.demo_mode'))
@push('scripts')
<script>
document.addEventListener('DOMContentLoaded', function() {
    const scanBtn = document.getElementById('scanBtn');
    const result = document.getElementById('result');
    const resultContent = document.getElementById('resultContent');
    let attemptNum = 0;

    // Check if WebNFC is supported
    if (!('NDEFReader' in window)) {
        scanBtn.disabled = true;
        scanBtn.textContent = 'WebNFC not supported';
        resultContent.innerHTML = '<div class="alert alert-danger">WebNFC is not supported in this browser. Please use Chrome for Android (version 89+).</div>';
        result.classList.remove('d-none');
        return;
    }

    scanBtn.addEventListener('click', async function() {
        try {
            const ndef = new NDEFReader();
            await ndef.scan();

            scanBtn.textContent = 'Scanning... (Tap your tag)';
            scanBtn.disabled = true;

            ndef.addEventListener('readingerror', () => {
                resultContent.innerHTML = '<div class="alert alert-danger">Error reading NFC tag.</div>';
                result.classList.remove('d-none');
                scanBtn.disabled = false;
                scanBtn.textContent = 'Scan NFC Tag';
            });

            ndef.addEventListener('reading', ({ message, serialNumber }) => {
                attemptNum++;

                for (const record of message.records) {
                    if (record.recordType === 'url') {
                        const decoder = new TextDecoder();
                        const url = decoder.decode(record.data);

                        resultContent.innerHTML = `
                            <p><strong>Attempt #${attemptNum}</strong></p>
                            <p><strong>Serial Number:</strong> ${serialNumber}</p>
                            <p><strong>URL:</strong></p>
                            <p><a href="${url}" class="btn btn-sm btn-primary" target="_blank">${url}</a></p>
                        `;
                        result.classList.remove('d-none');
                    }
                }

                scanBtn.disabled = false;
                scanBtn.textContent = 'Scan NFC Tag';
            });
        } catch (error) {
            resultContent.innerHTML = `<div class="alert alert-danger">Error: ${error.message}</div>`;
            result.classList.remove('d-none');
            scanBtn.disabled = false;
            scanBtn.textContent = 'Scan NFC Tag';
        }
    });
});
</script>
@endpush
@endif
