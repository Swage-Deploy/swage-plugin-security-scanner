<?php

namespace Swage\SecurityScanner;

use App\Plugins\HasPluginSettings;
use App\Servers\ServerIntegrations;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Support\ServiceProvider;
use Livewire\Livewire;
use Swage\SecurityScanner\Console\ReviewCommand;
use Swage\SecurityScanner\Console\ScanCommand;
use Swage\SecurityScanner\Livewire\SecurityPanel;
use Swage\SecurityScanner\Models\AiReview;
use Swage\SecurityScanner\Models\SecurityAlert;
use Swage\SecurityScanner\Models\SecurityEvent;

class SecurityScannerServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/security-scanner.php', 'security-scanner');

        // Swage v1.3.0 added plugin settings, which hold the AI review's API. Older versions get the scanner without it.
        $this->app->bind(SecurityScannerIntegration::class, interface_exists(HasPluginSettings::class)
            ? ConfigurableSecurityScannerIntegration::class
            : SecurityScannerIntegration::class);
    }

    /**
     * Register the integration and its panel, scan every few minutes, and check hourly for servers due an AI review.
     * Swage's own daily pruning only looks in its app/Models directory, so the scanner prunes its events, old alerts
     * and old reviews itself.
     */
    public function boot(): void
    {
        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
        $this->loadViewsFrom(__DIR__.'/../resources/views', 'security-scanner');

        Livewire::component('security-scanner.panel', SecurityPanel::class);

        $this->app->make(ServerIntegrations::class)->register(SecurityScannerIntegration::class);

        if ($this->app->runningInConsole()) {
            $this->commands([ScanCommand::class, ReviewCommand::class]);
        }

        $this->callAfterResolving(Schedule::class, function (Schedule $schedule): void {
            $interval = max(1, (int) config('security-scanner.interval'));

            $schedule->command('security-scanner:scan')->cron("*/{$interval} * * * *")->withoutOverlapping();
            $schedule->command('security-scanner:review')->hourly()->withoutOverlapping();
            $schedule->command('model:prune', ['--model' => [SecurityEvent::class, SecurityAlert::class, AiReview::class]])->daily();
        });
    }
}
