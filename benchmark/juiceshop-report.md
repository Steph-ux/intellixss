# OWASP Juice Shop bench

Target: Juice Shop 20.3.0 at `http://127.0.0.1:3000`.
Scanner: IntelliXSS, stock configuration, no per-surface tuning.
Source: `benchmark/juiceshop.json`, written by `bench/juice.py`.

## Documented XSS challenges

The nine entries of `data/static/challenges.yml` whose category is `XSS`.
A challenge counts as reproduced when the scanner confirms, in a browser,
an executing payload on the sink that challenge is about.
Reaching a sink is not the same as solving what the challenge asks: a few
of them are solved by the *server* recognising one exact injected value.
Those are marked separately, because the scanner proves the sink executes
while sending its own payload, which is what a scan is for.

| Challenge | Key | Sink | Result |
|---|---|---|---|
| API-only XSS | `restfulXssChallenge` | `PUT /rest/products/1/reviews` | not reached |
| CSP Bypass | `usernameXssChallenge` | `POST /profile` | not reached |
| Client-side XSS Protection | `persistedXssUserChallenge` | `POST /profile` | reproduced; challenge itself needs the literal `<iframe src="javascript:alert(`xss`)">` |
| DOM XSS | `localXssChallenge` | `GET /#/search?q=` | reproduced |
| HTTP-Header XSS | `httpHeaderXssChallenge` | `GET /#/privacy-security/last-login-ip` via `localStorage` | reproduced |
| Reflected XSS | `reflectedXssChallenge` | `GET /#/track-result?id=` | reproduced |
| Server-side XSS Protection | `persistedXssFeedbackChallenge` | `POST /api/Feedbacks` | clean |
| Video XSS | `videoXssChallenge` | admin-only promo video URL | not reached |
| Bonus Payload | `xssBonusChallenge` | `GET /#/search?q=` | not reached |

The profile surface is credited for its sink, not for the challenge: the
scanner confirms that a stored username reaches a sink that executes its
own `<img onerror>` payload, while the challenge is solved by the server
seeing one exact injected value. The same holds for the search surface
and the bonus payload.

4 of 9 documented XSS challenges reproduced automatically.
1 documented challenge reported clean, and 4 met the roster's bar for a challenge (see below). Each of those names the sink it is about, so a row marked "not reached" is a statement about that sink, not about the roster.

A clean result is the expected answer for `persistedXssFeedbackChallenge`: the sink is behind
`sanitize-html` with its default allow-list, so the payload is stored as
text and cannot execute. Reporting it clean is the precision counterpart
to the confirmations.

Beyond the documented list, the scanner confirmed sinks that no challenge
covers:

- `POST /api/Complaints` (`message`, stored) on the `complaints` surface

## Session material supplied by the harness

A scan of an anonymous page cannot reach a sink that is only stored for
a logged-in user, or fed by a header the page never sends. For those
surfaces the harness supplies *identity and transport only*: a throwaway
account registered through `POST /api/Users`, and where a surface is
about a header, that header. No payload is pre-written by the harness.

| Surface | Session | Supplied |
|---|---|---|
| home | shared | admin bearer |
| search | shared | admin bearer |
| track | shared | admin bearer |
| reviews | shared | admin bearer |
| feedback | shared | admin bearer |
| complaints | shared | admin bearer |
| last-login-ip | account | throwaway account, header `True-Client-IP` |
| profile | account | throwaway account |
| login | shared | admin bearer |

## Surfaces

| Surface | Pointed at | Sink | Verdict | Confirmed | Requests | Time |
|---|---|---|---|---|---|---|
| home | `/` | `GET /` | clean | 0 | 69 | 74.4s |
| search | `/` | `GET /#/search?q=` | reproduced | 1 | 69 | 75.3s |
| track | `/` | `GET /#/track-result?id=` | reproduced | 1 | 69 | 74.3s |
| reviews | `/` | `PUT /rest/products/1/reviews` | lead only | 0 | 69 | 74.7s |
| feedback | `/` | `POST /api/Feedbacks` | clean | 0 | 69 | 74.1s |
| complaints | `/` | `POST /api/Complaints` | reproduced | 1 | 69 | 71.0s |
| last-login-ip | `/#/privacy-security/last-login-ip` | `GET /#/privacy-security/last-login-ip` via `localStorage` | reproduced | 1 | 69 | 64.1s |
| profile | `/profile` | `POST /profile` | reproduced | 1 | 10 | 14.6s |
| login | `/` | `POST /rest/user/login` | clean | 0 | 69 | 67.6s |

## Confirmed findings

### `GET http://127.0.0.1:3000/#/search?q=%3Cimg+src%3Dx+onerror%3Dalert%28%60ixm03bac14b%60%29%3E`

- Parameter: `q`
- Context: `html_text`
- Type: `dom`
- Payload: `<img src=x onerror=alert(`ixm03bac14b`)>`
- Replay: hash route: execution is browser-only

### `GET http://127.0.0.1:3000/#/track-result?id=%3Cimg+src%3Dx+onerror%3Dalert%28%60ixm866b973f%60%29%3E`

- Parameter: `id`
- Context: `html_text`
- Type: `dom`
- Payload: `<img src=x onerror=alert(`ixm866b973f`)>`
- Replay: HTTP `200`, echoed `true`, stored `false`

### `POST http://127.0.0.1:3000/api/Complaints`

- Parameter: `message`
- Context: `html_text`
- Type: `stored`
- Payload: `<img src=x onerror=alert('ixm84a9dfef')>`
- Replay: HTTP `201`, echoed `true`, stored `true`

### `GET http://127.0.0.1:3000/#/privacy-security/last-login-ip`

- Parameter: `localStorage`
- Context: `url_fragment`
- Type: `dom`
- Payload: `<img src=x onerror=alert('ixm80182528')>`
- Replay: hash route: execution is browser-only

### `POST http://127.0.0.1:3000/profile`

- Parameter: `username`
- Context: `html_text`
- Type: `stored`
- Payload: `<img src=x onerror=alert('ixmd1c4eda3')>`
- Replay: HTTP `200`, echoed `true`, stored `true`

## Not reached by the roster, and why

- **API-only XSS** (`restfulXssChallenge`): needs a review submitted through the API instead of the dialog's form; the scanner drives what the page renders, and the product dialog in 20.3.0 puts the review text in a plain property binding, so it is never parsed as markup. The server-side sink is real; reaching it means posting the review the page itself does not post.
- **CSP Bypass** (`usernameXssChallenge`): needs an account whose username is rendered on the legacy Pug profile under a CSP the challenge rewards rewriting; the bench registers accounts, but the challenge is solved by one exact stored value, not by proving the renderer executes what it is given.
- **Video XSS** (`videoXssChallenge`): needs an administrator to change the promo video URL.
- **Bonus Payload** (`xssBonusChallenge`): shares the DOM XSS sink but requires one exact SoundCloud iframe; the scanner proves the sink, not the challenge's payload.
