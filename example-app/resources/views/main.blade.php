@extends('layouts.app')

@section('title', 'SDM Backend Server' . (config('sdm.demo_mode') ? ' Example' : ''))

@section('content')
    <h1 class="mb-4">
        Secure Dynamic Messaging Backend Server
        @if(config('sdm.demo_mode'))
            Example
        @endif
    </h1>

    @if(config('sdm.demo_mode'))
        <div class="mb-4">
            <p>
                The examples below are from
                <a href="https://www.nxp.com/docs/en/application-note/AN12196.pdf" target="_blank">NXP AN12196</a>.
            </p>

            <ul class="list-unstyled">
                <li class="mb-2">
                    <strong>Plaintext UID with mirrored Read Counter and CMAC (NTAG 424 DNA variant):</strong><br>
                    <a href="/tagpt?uid=041E3C8A2D6B80&ctr=000006&cmac=4B00064004B0B3D3">
                        /tagpt?uid=041E3C8A2D6B80&ctr=000006&cmac=4B00064004B0B3D3
                    </a>
                </li>

                <li class="mb-2">
                    <strong>Encrypted PICCData (NTAG 424 DNA variant):</strong><br>
                    <a href="/tag?picc_data=EF963FF7828658A599F3041510671E88&cmac=94EED9EE65337086">
                        /tag?picc_data=EF963FF7828658A599F3041510671E88&cmac=94EED9EE65337086
                    </a>
                </li>

                <li class="mb-2">
                    <strong>Encrypted PICCData (LRP mode, 24 bytes):</strong><br>
                    <a href="/tag?picc_data=1FCBE61B3E4CAD980CBFDD333E7A4AC4A579569BAFD22C5F&cmac=4231608BA7B02BA9">
                        /tag?picc_data=1FCBE61B3E4CAD980CBFDD333E7A4AC4A579569BAFD22C5F&cmac=4231608BA7B02BA9
                    </a>
                </li>

                <li class="mb-2">
                    <strong>Encrypted PICCData and SDMFileData (NTAG 424 DNA variant):</strong><br>
                    <a href="/tag?picc_data=FD91EC264309878BE6345CBE53BADF40&enc=CEE9A53E3E463EF1F459635736738962&cmac=ECC1E7F6C6C73BF6">
                        /tag?picc_data=FD91EC264309878BE6345CBE53BADF40&enc=CEE9A53E3E463EF1F459635736738962&cmac=ECC1E7F6C6C73BF6
                    </a>
                </li>

                <li class="mb-2">
                    <strong>Encrypted PICCData and SDMFileData (NTAG 424 DNA TagTamper variant):</strong><br>
                    <a href="/tagtt?picc_data=FDD387BF32A33A7C40CF259675B3A1E2&enc=EA050C282D8E9043E28F7A171464D697&cmac=758110182134ECE9">
                        /tagtt?picc_data=FDD387BF32A33A7C40CF259675B3A1E2&enc=EA050C282D8E9043E28F7A171464D697&cmac=758110182134ECE9
                    </a>
                </li>

                <li class="mb-2">
                    <strong>Encrypted PICCData and SDMFileData (NTAG 424 DNA TagTamper variant, LRP mode, 24 bytes):</strong><br>
                    <a href="/tagtt?picc_data=8EE8E27DE3974FFE245F96C71087129B2E8449C9FF346F65&enc=48987A0D55638C017D1F4DC3D8ADD910&cmac=862E781E52244A75">
                        /tagtt?picc_data=8EE8E27DE3974FFE245F96C71087129B2E8449C9FF346F65&enc=48987A0D55638C017D1F4DC3D8ADD910&cmac=862E781E52244A75
                    </a>
                </li>

                <li class="mb-2">
                    <strong>WebNFC Example (Chrome for Android only):</strong><br>
                    <a href="/webnfc">/webnfc</a>
                </li>
            </ul>
        </div>
    @endif
@endsection
