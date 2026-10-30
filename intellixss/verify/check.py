"""Verify whether a probe response indicates XSS / block."""

from __future__ import annotations

from typing import Dict, List, Optional

from intellixss.analysis.filters import classify_filters
from intellixss.analysis.reflection import find_reflection, is_payload_effective, reflection_score
from intellixss.models import (
    BlockDiagnosis,
    BlockReason,
    FilterType,
    InjectionContext,
    ProbeOutcome,
    XSSFinding,
)


def evaluate_response(
    url: str,
    param: str,
    method: str,
    payload: str,
    status: int,
    body: str,
    headers: Optional[Dict[str, str]],
    context: InjectionContext,
    filters: Optional[List[FilterType]] = None,
) -> ProbeOutcome:
    """Pure evaluation of one injection attempt."""
    headers = headers or {}

    if status == 0:
        diag = BlockDiagnosis(
            reason=BlockReason.NETWORK_ERROR,
            status=0,
            detail="Network error or empty response",
        )
        return ProbeOutcome(
            success=False,
            payload=payload,
            reflected=False,
            status=status,
            diagnosis=diag,
        )

    filt_list, diag = classify_filters(
        body, payload, headers=headers, status=status, original_payload=payload
    )
    if filters:
        # merge known filters
        for f in filters:
            if f not in filt_list:
                filt_list.append(f)

    score = reflection_score(body, payload)
    reflected = score > 0
    effective, evidence_tag = is_payload_effective(body, payload, context.value)

    if status >= 400 and not effective:
        return ProbeOutcome(
            success=False,
            payload=payload,
            reflected=reflected,
            status=status,
            diagnosis=diag if diag.reason != BlockReason.NONE else BlockDiagnosis(
                reason=BlockReason.HTTP_STATUS,
                status=status,
                detail=f"HTTP {status}",
            ),
        )

    # An error page is still a rendered document: a 400/500 that echoes the
    # payload as live markup is exactly as exploitable as a 200. The status
    # class decides what a *scanner* should retry, not what a browser executes.
    if effective:
        snippet = find_reflection(body, payload) or evidence_tag
        finding = XSSFinding(
            url=url,
            parameter=param,
            method=method,
            context=context,
            payload=payload,
            evidence=f"{evidence_tag}: {snippet[:180]}",
            browser_confirmed=False,
            impact="high",
            vulnerability_type="reflected" if method.upper() == "GET" else "stored_or_post",
            filters_bypassed=[f for f in filt_list if f != FilterType.NO_FILTER],
            confidence=min(0.95, 0.55 + score * 0.4),
        )
        return ProbeOutcome(
            success=True,
            payload=payload,
            reflected=True,
            status=status,
            finding=finding,
            diagnosis=None,
        )

    if not reflected:
        if diag.reason == BlockReason.NONE:
            diag = BlockDiagnosis(
                reason=BlockReason.NO_REFLECTION,
                status=status,
                detail="Payload not reflected",
            )
        return ProbeOutcome(
            success=False,
            payload=payload,
            reflected=False,
            status=status,
            diagnosis=diag,
        )

    # Reflected but not effective
    if diag.reason == BlockReason.NONE:
        diag = BlockDiagnosis(
            reason=BlockReason.FILTERED_PAYLOAD,
            status=status,
            detail=f"Reflected but not executable ({evidence_tag})",
            signals=[evidence_tag],
        )
    return ProbeOutcome(
        success=False,
        payload=payload,
        reflected=True,
        status=status,
        diagnosis=diag,
    )
