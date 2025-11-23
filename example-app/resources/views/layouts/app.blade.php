<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>@yield('title', 'SDM Backend')</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    @stack('styles')
</head>
<body>
    <div class="container my-5">
        @yield('content')

        @hasSection('footer')
            @yield('footer')
        @else
            <footer class="mt-5">
                @if(config('sdm.demo_mode'))
                    <div class="alert alert-info">
                        This is an example deployment of the open source
                        <a href="https://github.com/kduma-autoid/php-sdm" target="_blank">php-sdm</a>
                        library.
                    </div>
                    <div class="alert alert-info">
                        Based on the Python implementation from
                        <a href="https://github.com/nfc-developer/sdm-backend" target="_blank">nfc-developer/sdm-backend</a>.
                    </div>
                @endif

                <div class="text-center text-muted mt-4">
                    <small>&copy; {{ date('Y') }} - Powered by php-sdm</small>
                </div>
            </footer>
        @endif
    </div>

    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.5.2/dist/js/bootstrap.bundle.min.js"></script>
    @stack('scripts')
</body>
</html>
