# OWASP Juice Shop bench

Target: Juice Shop 20.3.0 at `http://127.0.0.1:3000`.
Scanner: IntelliXSS, stock configuration, no per-surface tuning.
Source: `benchmark/juiceshop.json`, written by `bench/juice.py`.

## Documented XSS challenges

The nine entries of `data/static/challenges.yml` whose category is `XSS`.
A challenge counts as reproduced when the scanner confirms, in a browser,
an executing payload on the sink that challenge is about.

| Challenge | Key | Sink | Result |
|---|---|---|---|
| API-only XSS | `restfulXssChallenge` | `PUT /rest/products/1/reviews` | reproduced |
| CSP Bypass | `usernameXssChallenge` | not reached | not reached |
| Client-side XSS Protection | `persistedXssUserChallenge` | not reached | not reached |
| DOM XSS | `localXssChallenge` | `GET /#/search?q=` | reproduced |
| HTTP-Header XSS | `httpHeaderXssChallenge` | not reached | not reached |
| Reflected XSS | `reflectedXssChallenge` | not reached | not reached |
| Server-side XSS Protection | `persistedXssFeedbackChallenge` | `POST /api/Feedbacks` | clean |
| Video XSS | `videoXssChallenge` | not reached | not reached |
| Bonus Payload | `xssBonusChallenge` | not reached | not reached |

2 of 9 documented XSS challenges reproduced automatically.
1 documented challenge reported clean, and 6 were not reached by this roster (see below).

A clean result is the expected answer for `persistedXssFeedbackChallenge`: the sink is behind
`sanitize-html` with its default allow-list, so the payload is stored as
text and cannot execute. Reporting it clean is the precision counterpart
to the confirmations.

Beyond the documented list, the scanner confirmed sinks that no challenge
covers:

- `POST /api/Complaints` (`message`, stored) on the `complaints` surface

## Surfaces

| Surface | Pointed at | Sink | Verdict | Confirmed | Requests | Time |
|---|---|---|---|---|---|---|
| home | `/` | `GET /` | clean | 0 | 68 | 51.3s |
| search | `/` | `GET /#/search?q=` | reproduced | 1 | 68 | 52.1s |
| reviews | `/` | `PUT /rest/products/1/reviews` | reproduced | 1 | 68 | 51.8s |
| feedback | `/` | `POST /api/Feedbacks` | clean | 0 | 68 | 54.8s |
| complaints | `/` | `POST /api/Complaints` | reproduced | 1 | 68 | 51.5s |
| login | `/` | `POST /rest/user/login` | clean | 0 | 68 | 51.8s |

## Confirmed findings

### `GET http://127.0.0.1:3000/#/search?q=%3Cimg+src%3Dx+onerror%3Dalert%28%27ixm03bac14b%27%29%3E`

- Parameter: `q`
- Context: `html_text`
- Type: `dom`
- Payload: `<img src=x onerror=alert('ixm03bac14b')>`
- Replay: hash route, execution is browser-only

### `PUT http://127.0.0.1:3000/rest/products/1/reviews`

- Parameter: `message`
- Context: `html_text`
- Type: `stored`
- Payload: `<img src=x onerror=alert('ixm9638094e')>`
- Replay: HTTP `201`, echoed `false`, stored `true`

### `POST http://127.0.0.1:3000/api/Complaints`

- Parameter: `message`
- Context: `html_text`
- Type: `stored`
- Payload: `<img src=x onerror=alert('ixmdd205bea')>`
- Replay: HTTP `201`, echoed `true`, stored `true`

## Not reached, and why

- **CSP Bypass** (`usernameXssChallenge`): needs an account whose username is rendered on a legacy page under CSP; the roster does not register users.
- **Client-side XSS Protection** (`persistedXssUserChallenge`): needs a registered user's username persisted and a client-side sanitizer bypass; the roster does not register users.
- **HTTP-Header XSS** (`httpHeaderXssChallenge`): the sink is a request header persisted and rendered in the admin area; no surface sends attacker-controlled headers.
- **Reflected XSS** (`reflectedXssChallenge`): the order-tracking page reflects the id returned by its API; the roster does not drive that page with a live order.
- **Video XSS** (`videoXssChallenge`): needs an administrator to change the promo video URL.
- **Bonus Payload** (`xssBonusChallenge`): shares the DOM XSS sink but requires one exact SoundCloud iframe; the scanner proves the sink, not the challenge's payload.
