<?php

namespace Laravel\Jetstream\Http\Controllers\Inertia;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Date;
use Laravel\Jetstream\Jetstream;
use Laravel\Passport\Client;
use Laravel\Passport\Contracts\CreatesClients;
use Laravel\Passport\Contracts\UpdatesClients;
use Laravel\Passport\Token;

class OAuthAppController extends Controller
{
    /**
     * Show the user OAuth app screen.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Inertia\Response
     */
    public function index(Request $request)
    {
        return Jetstream::inertia()->render($request, 'OAuth/Index', [
            'connections' => $request->user()->tokens()
                ->with('client')
                ->where('revoked', false)
                ->where('expires_at', '>', Date::now())
                ->get()
                ->reject(fn (Token $token) => $token->client->revoked || $token->client->hasGrantType('personal_access'))
                ->groupBy('client_id')
                ->map(fn ($tokens) => [
                    'client' => $tokens->first()->client,
                    'scopes' => $tokens->pluck('scopes')->flatten()->unique()->all(),
                    'tokens_count' => $tokens->count(),
                ]),
            'apps' => $request->user()->clients()
                ->where('revoked', false)
                ->get()
                ->map(fn (Client $client) => $client->toArray() + [
                    'is_confidential' => $client->confidential(),
                    'created_date' => $client->created_at->toFormattedDateString(),
                ]),
        ]);
    }

    /**
     * Create a new OAuth app.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\RedirectResponse
     */
    public function store(Request $request)
    {
        $client = app(CreatesClients::class)->create($request->all());

        return back()->with('flash', [
            'client_id' => $client->id,
            'client_secret' => $client->plainSecret,
        ]);
    }

    /**
     * Update the given OAuth app.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $clientId
     * @return \Illuminate\Http\RedirectResponse
     */
    public function update(Request $request, $clientId)
    {
        $client = $request->user()->clients()->findOrFail($clientId);

        app(UpdatesClients::class)->update($client, $request->all());

        return back(303);
    }

    /**
     * Delete the given OAuth App.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $clientId
     * @return \Illuminate\Http\RedirectResponse
     */
    public function destroy(Request $request, $clientId)
    {
        $client = $request->user()->clients()->find($clientId);

        $client->tokens()->each(function (Token $token) {
            $token->refreshToken->revoke();
            $token->revoke();
        });

        $client->revoke();

        return back(303);
    }
}
