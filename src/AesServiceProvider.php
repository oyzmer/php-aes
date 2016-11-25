<?php

namespace Oyzmer\phpAes;

use Illuminate\Support\ServiceProvider;

class AesServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap the application services.
     *
     * @return void
     */
    public function boot()
    {
        $this->publishes([
            __DIR__.'/config/aes.php' => config_path('aes.php'),
        ]);
    }

    /**
     * Register the application services.
     *
     * @return void
     */
    public function register()
    {
        $this->app['aes'] = $this->app->share(function ($app) {
            return new Aes($app['config']);
        });
    }
    
    /**
     * Get the services provided by the provider.
     *
     * @return array
     */
    public function provides()
    {
        return ['Aes'];
    }
}
