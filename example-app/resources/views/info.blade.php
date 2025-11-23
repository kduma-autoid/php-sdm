@extends('layouts.app')

@section('title', 'SDM Backend Server Demo')

@section('content')
    <h1 class="mb-4">Secure Dynamic Messaging Backend Server Demo</h1>

    <div class="alert alert-success">
        <strong>Cryptographic signature validated</strong>
    </div>

    @if(isset($piccDataTag))
        <p>
            <strong>PICCDataTag:</strong>
            <code>{{ strtoupper(bin2hex($piccDataTag)) }}</code>
        </p>
    @endif

    <p>
        <strong>Encryption mode:</strong>
        <span class="badge badge-{{ $encryptionMode === 'LRP' ? 'success' : 'secondary' }}">
            {{ $encryptionMode }}
        </span>
    </p>

    <p>
        <strong>Tag UID:</strong>
        <code>{{ strtoupper(bin2hex($uid)) }}</code>
    </p>

    <p>
        <strong>Read counter:</strong>
        <code>{{ $readCtr }}</code>
    </p>

    @if(isset($fileData))
        <p>
            <strong>File data (raw):</strong>
            <code>{{ strtoupper(bin2hex($fileData)) }}</code>
        </p>

        <p>
            <strong>File data (UTF-8):</strong>
            <code>{{ $fileDataUtf8 }}</code>
        </p>
    @endif

    @if(isset($tamperStatus))
        <div class="mt-4">
            <p><em>(Assuming that "Tamper Status" is stored in the first two bytes of "File data")</em></p>
            <p>
                <strong>Tamper status:</strong>
                <span class="badge badge-{{ $tamperColor }}">{{ $tamperStatus }}</span>
            </p>
        </div>
    @endif

    <div class="mt-4">
        <a href="{{ request()->fullUrlWithQuery(['output' => 'json']) }}" class="btn btn-primary">
            View as JSON
        </a>

        @if(config('sdm.demo_mode'))
            <a href="/" class="btn btn-secondary ml-2">Back</a>
        @endif
    </div>
@endsection
