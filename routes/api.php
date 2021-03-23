<?php

Route::prefix('api')->group(function () {
    Route::middleware('api')->group(function() {
        Route::post('/oauth2/introspect',
            [\Frengky\PassportIntrospect\PassportIntrospectController::class, 'introspect']);
    });
});
