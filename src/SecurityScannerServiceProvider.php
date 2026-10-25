<?php

namespace Swage\SecurityScanner;

use App\Servers\ServerIntegrations;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Support\ServiceProvider;
use Livewire\Livewire;
use Swage\SecurityScanner\Console\ScanCommand;
use Swage\SecurityScanner\Livewire\SecurityPanel;
use Swage\SecurityScanner\Models\SecurityAlert;
use Swage\SecurityScanner\Models\SecurityEvent;

class SecurityScannerServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/security-scanner.php', 'security-scanner');
    }

    /**
     * Register the integration and its panel, and scan every few minutes. Swage's own daily pruning only looks in its
     * app/Models directory, so the scanner prunes its events and old alerts itself.
     */
    public function boot(): void
    {
        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
        $this->loadViewsFrom(__DIR__.'/../resources/views', 'security-scanner');

        Livewire::component('security-scanner.panel', SecurityPanel::class);

        $this->app->make(ServerIntegrations::class)->register(SecurityScannerIntegration::class);

        if ($this->app->runningInConsole()) {
            $this->commands([ScanCommand::class]);
        }

        $this->callAfterResolving(Schedule::class, function (Schedule $schedule): void {
            $interval = max(1, (int) config('security-scanner.interval'));

            $schedule->command('security-scanner:scan')->cron("*/{$interval} * * * *")->withoutOverlapping();
            $schedule->command('model:prune', ['--model' => [SecurityEvent::class, SecurityAlert::class]])->daily();
        });
    }
}
