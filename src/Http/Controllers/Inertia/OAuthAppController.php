<?php

namespace Laravel\Jetstream\Http\Controllers\Inertia;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Collection;
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
        return Jetstream::inertia()->render($request, 'API/Index', [
            'authorizedApps' => $request->user()->tokens()
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
                }, collect()),
            'oauthApps' => $request->user()->clients()
                ->where('revoked', false)
                ->orderBy('name', 'asc')
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
        $request->user()->clients()->find($clientId)->delete();

        return back(303);
    }
}
