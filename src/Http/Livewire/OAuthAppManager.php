<?php

namespace Laravel\Jetstream\Http\Livewire;

use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Date;
use Illuminate\View\View;
use Laravel\Passport\Client;
use Laravel\Passport\Contracts\CreatesClients;
use Laravel\Passport\Contracts\UpdatesClients;
use Laravel\Passport\Token;
use Livewire\Attributes\On;
use Livewire\Component;

class OAuthAppManager extends Component
{
    /**
     * The user's authorized apps.
     *
     * @var \Illuminate\Database\Eloquent\Collection<int, array>
     */
    public $authorizedApps;

    /**
     * The user's OAuth apps.
     *
     * @var \Illuminate\Database\Eloquent\Collection<int, \Laravel\Passport\Client>
     */
    public $oauthApps;

    /**
     * Create OAuth app form state.
     *
     * @var array<string, mixed>
     */
    public array $createOAuthAppForm = [
        'name' => '',
        'redirect_uri' => '',
        'confidential' => false,
    ];

    /**
     * Indicates if the client credentials is being displayed to the user.
     */
    public bool $displayingClientCredentials = false;

    /**
     * The client credentials.
     */
    public array $clientCredentials = [
        'id' => null,
        'secret' => null,
    ];

    /**
     * Indicates if the application is confirming if a authorized app should be revoked.
     */
    public bool $confirmingAuthorizedAppRevocation = false;

    /**
     * The ID of the authorized app being revoked.
     */
    public string $authorizedAppIdBeingRevoked;

    /**
     * Indicates if the user is currently managing an OAuth app.
     *
     * @var bool
     */
    public bool $managingOAuthApp = false;

    /**
     * The OAuth app that is currently being managed.
     *
     * @var \Laravel\Passport\Client|null
     */
    public ?Client $oauthAppBeingManaged;

    /**
     * The update OAuth app form state.
     *
     * @var array
     */
    public array $updateOAuthAppForm = [
        'name' => '',
        'redirect_uri' => '',
    ];

    /**
     * Indicates if the application is confirming if a OAuth app should be deleted.
     */
    public bool $confirmingOAuthAppDeletion = false;

    /**
     * The ID of the OAuth app being deleted.
     */
    public string $oauthAppIdBeingDeleted;

    /**
     * Mount the component.
     */
    public function mount(): void
    {
        $this->loadAuthorizedApps();
        $this->loadOAuthApps();
    }

    /**
     * Render the component.
     */
    public function render(): View
    {
        return view('oauth.oauth-app-manager');
    }

    /**
     * Get the current user of the application.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable
     */
    public function getUserProperty()
    {
        return Auth::user();
    }

    /**
     * Load the user's authorized apps.
     */
    #[On('authorized-app-revoked')]
    public function loadAuthorizedApps(): void
    {
        $this->authorizedApps = $this->user->tokens()
            ->with('client')
            ->where('revoked', false)
            ->where('expires_at', '>', Date::now())
            ->get()
            ->reduce(function (Collection $apps, Token $token) {
                if ($token->client->revoked || $token->client->personal_access_client) {
                    return $apps;
                }

                $app = $apps->get($token->client_id);

                if ($app) {
                    $app['scopes'] = array_unique(array_merge($app['scopes'], $token->scopes));
                    $app['tokens_count'] += 1;

                    $apps->put($token->client_id, $app);
                } else {
                    $apps->put($token->client_id, [
                        'client' => $token->client,
                        'scopes' => $token->scopes,
                        'tokens_count' => 1,
                    ]);
                }

                return $apps;
            }, collect());
    }

    /**
     * Load the user's OAuth apps.
     */
    #[On(['oauth-app-created', 'oauth-app-updated', 'oauth-app-deleted'])]
    public function loadOAuthApps(): void
    {
        $this->oauthApps = $this->user->clients()
            ->where('revoked', false)
            ->orderBy('name', 'asc')
            ->get();
    }

    /**
     * Create a new OAuth Client.
     */
    public function createOAuthApp(CreatesClients $creator): void
    {
        $this->resetErrorBag();

        $this->displayClientCredentials(
            $creator->create($this->createOAuthAppForm)
        );

        $this->createOAuthAppForm['name'] = '';
        $this->createOAuthAppForm['redirect_uri'] = '';
        $this->createOAuthAppForm['confidential'] = false;

        $this->dispatch('oauth-app-created');
    }

    /**
     * Display the token value to the user.
     */
    protected function displayClientCredentials(Client $client): void
    {
        $this->displayingClientCredentials = true;

        $this->clientCredentials = [
            'id' => $client->id,
            'secret' => $client->plainSecret,
        ];

        $this->dispatch('client-credentials-displayed');
    }

    /**
     * Allow the given OAuth app to be managed.
     */
    public function manageOAuthApp(string $clientId): void
    {
        $this->managingOAuthApp = true;

        $this->oauthAppBeingManaged = $this->oauthApps->find($clientId);

        $this->updateOAuthAppForm['name'] = $this->oauthAppBeingManaged->name;
        $this->updateOAuthAppForm['redirect_uri'] = $this->oauthAppBeingManaged->redirect;
    }

    /**
     * Update the OAuth app.
     */
    public function updateOAuthApp(UpdatesClients $updater): void
    {
        $updater->update($this->oauthAppBeingManaged, $this->updateOAuthAppForm);

        $this->dispatch('oauth-app-updated');

        $this->managingOAuthApp = false;
    }

    /**
     * Confirm that the given OAuth app should be deleted.
     */
    public function confirmOAuthAppDeletion(string $clientId): void
    {
        $this->confirmingOAuthAppDeletion = true;

        $this->oauthAppIdBeingDeleted = $clientId;
    }

    /**
     * Delete the OAuth app.
     */
    public function deleteOAuthApp(): void
    {
        $this->oauthApps->find($this->oauthAppIdBeingDeleted)->delete();

        $this->dispatch('oauth-app-deleted');

        $this->confirmingOAuthAppDeletion = false;
    }

    /**
     * Confirm that the given authorized app should be revoked.
     */
    public function confirmAuthorizedAppRevocation(string $tokenId): void
    {
        $this->confirmingAuthorizedAppRevocation = true;

        $this->authorizedAppIdBeingRevoked = $tokenId;
    }

    /**
     * Revoke the authorized app.
     */
    public function revokeAuthorizedApp(): void
    {
        $this->user->tokens()
            ->where('client_id', $this->authorizedAppIdBeingRevoked)
            ->each(function (Token $token) {
                $token->refreshToken->revoke();
                $token->revoke();
            });

        $this->dispatch('authorized-app-revoked');

        $this->confirmingAuthorizedAppRevocation = false;
    }
}
