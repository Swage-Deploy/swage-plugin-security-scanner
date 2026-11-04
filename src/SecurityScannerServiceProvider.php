<?php

namespace Swage\SecurityScanner;

use App\Notifications\ServerAlert;
use App\Plugins\HasAttention;
use App\Servers\ServerIntegrations;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;
use Livewire\Livewire;
use Swage\SecurityScanner\Console\ScanCommand;
use Swage\SecurityScanner\Events\AlertRaised;
use Swage\SecurityScanner\Listeners\SendAlertNotification;
use Swage\SecurityScanner\Livewire\SecurityPanel;
use Swage\SecurityScanner\Models\SecurityAlert;
use Swage\SecurityScanner\Models\SecurityEvent;

class SecurityScannerServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/security-scanner.php', 'security-scanner');

        // Swage v1.3.3 added the badges on servers that need looking at. Older versions get the scanner without them.
        if (interface_exists(HasAttention::class)) {
            $this->app->bind(SecurityScannerIntegration::class, AttentiveSecurityScannerIntegration::class);
        }
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

        // Swage v1.3.16 added notifications. Older versions show alerts only on the scanner's tab.
        if (class_exists(ServerAlert::class)) {
            Event::listen(AlertRaised::class, SendAlertNotification::class);
        }

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
