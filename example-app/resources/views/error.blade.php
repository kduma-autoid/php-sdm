@extends('layouts.app')

@section('title', 'Error - SDM Backend Server Demo')

@section('content')
    <h1 class="mb-4">Secure Dynamic Messaging Backend Server Demo</h1>

    <div class="alert alert-danger">
        <strong>{{ $message }}</strong>
    </div>

    <hr>

    <div class="mt-4">
        <a href="/" class="btn btn-secondary">Back to Home</a>
    </div>
@endsection

@section('footer')
    {{-- Empty footer to override the default --}}
@endsection
