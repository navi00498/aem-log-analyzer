"""Known AEM issue signatures and remediation hints.

Rules are evaluated in order and the first match wins, so more specific rules come first.
Hints are general guidance based on public Apache Sling / Jackrabbit Oak / AEM documentation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional, Pattern, Tuple

SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_ORDER = {name: rank for rank, name in enumerate(SEVERITIES)}

DEFAULT_LEVELS = ("ERROR", "WARN")


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    pattern: Pattern[str]
    hint: str
    levels: Optional[Tuple[str, ...]] = DEFAULT_LEVELS
    extract: Optional[Pattern[str]] = None

    def applies_to(self, level: str) -> bool:
        return self.levels is None or level in self.levels


def _rule(id, title, severity, pattern, hint, levels=DEFAULT_LEVELS, extract=None, flags=0):
    return Rule(
        id=id,
        title=title,
        severity=severity,
        pattern=re.compile(pattern, flags),
        hint=hint,
        levels=levels,
        extract=re.compile(extract) if extract else None,
    )


RULES = (
    _rule(
        "jvm-oom",
        "JVM OutOfMemoryError",
        "critical",
        r"java\.lang\.OutOfMemoryError|GC overhead limit exceeded",
        "Capture a heap dump (-XX:+HeapDumpOnOutOfMemoryError) and review the dominator tree in Eclipse "
        "MAT. Common causes: unbounded queries, leaked ResourceResolvers/Sessions and oversized caches.",
        levels=None,
        extract=r"(java\.lang\.OutOfMemoryError: [^\n]+)",
    ),
    _rule(
        "oak-query-limit",
        "Oak query aborted after hitting the read/traversal limit",
        "high",
        r"The query read or traversed more than \d+ nodes",
        "Oak cancelled a query that read too many nodes. Add or fix an Oak index for the query and "
        "check its explain plan before raising any limits.",
    ),
    _rule(
        "oak-traversal",
        "Oak queries traversing the repository (missing index)",
        "high",
        r"Traversed \d+ nodes",
        "Traversal queries get slower as content grows. Create a matching Lucene/property index or "
        "rewrite the query to use an existing one, then verify with the query explain plan.",
        extract=r"query=(.+?)(?:, path=|\);|$)",
    ),
    _rule(
        "oak-index-corrupt",
        "Oak/Lucene index corruption or copy failure",
        "high",
        r"CorruptIndexException|index [^\n]{0,80} corrupt|IndexCopier[^\n]*(?:fail|corrupt)",
        "Identify the affected index, check its status in the IndexStats MBean and plan a reindex "
        "during low traffic.",
        flags=re.IGNORECASE,
    ),
    _rule(
        "oak-async-index",
        "Async index update failing",
        "medium",
        r"AsyncIndexUpdate[^\n]*(?:fail|lease)|The index update (?:failed|interrupted)",
        "Search results will become stale while async indexing is failing. Resolve the reported "
        "exception and confirm the async lane resumes in the IndexStats MBean.",
    ),
    _rule(
        "service-user-mapping",
        "Missing service user mapping",
        "high",
        r"Cannot derive user name for bundle|No service user mapping",
        "Add a ServiceUserMapperImpl.amended configuration and create the service user and its ACLs "
        "with repoinit.",
        extract=r"(bundle \S+(?: \[\d+\])? and sub service \S+)",
    ),
    _rule(
        "unclosed-resolver",
        "Leaked ResourceResolver / JCR session",
        "medium",
        r"Unclosed ResourceResolver|unclosed session|This session has been idle for",
        "Close ResourceResolvers and Sessions in finally blocks or use try-with-resources. Leaks cause "
        "memory growth and stale reads.",
        extract=r"at ((?!org\.apache\.|java\.|sun\.|com\.day\.|com\.adobe\.)[\w$.]+)\(",
    ),
    _rule(
        "replication",
        "Replication / content distribution failures",
        "high",
        r"ReplicationException|com\.day\.cq\.replication\.|Replication (?:action|job)[^\n]*fail"
        r"|distribution[^\n]*(?:fail|blocked)",
        "Check replication agent or Sling Content Distribution queue status, transport credentials and "
        "publish availability. Blocked queues delay content activation.",
        levels=("ERROR",),
        flags=re.IGNORECASE,
    ),
    _rule(
        "osgi-component",
        "OSGi bundle/component failed to resolve or activate",
        "high",
        r"Unable to resolve|FrameworkEvent ERROR|The activate method has thrown an exception"
        r"|Cannot register component",
        "Check /system/console/bundles and /system/console/components for unresolved imports or "
        "failed activations. Align dependency versions with the AEM SDK / uber-jar.",
        extract=r"\[([\w.$]+)\(\d+\)\]",
    ),
    _rule(
        "sling-uncaught",
        "Uncaught exceptions while rendering requests (HTTP 500)",
        "high",
        r"Uncaught (?:Throwable|SlingException)|SlingRequestProcessorImpl service: Uncaught",
        "Unhandled exceptions in components, Sling Models or servlets return 500s. Fix the root cause "
        "in the stack trace and add defensive null checks in models.",
        extract=r"at ((?!org\.apache\.|java\.|javax\.|sun\.|jdk\.|com\.day\.|com\.adobe\.)[\w$.]+)\(",
    ),
    _rule(
        "oak-commit-conflict",
        "Oak commit conflicts",
        "medium",
        r"OakState\d{4}|OakMerge\d{4}|CommitFailedException",
        "Concurrent writes conflict on the same nodes. Reduce concurrent updates to hot nodes, retry "
        "with backoff and avoid long-lived sessions.",
    ),
    _rule(
        "workflow",
        "Workflow failures",
        "medium",
        r"com\.adobe\.granite\.workflow|WorkflowException|com\.day\.cq\.workflow",
        "Review failed workflow instances, purge stale instances and check custom process steps.",
        levels=("ERROR",),
    ),
    _rule(
        "auth-sso",
        "Authentication / SSO (SAML) errors",
        "medium",
        r"LoginException|SAML|Authentication failed|AuthenticationHandler",
        "Verify IdP metadata and certificates, the SAML authentication handler configuration and "
        "user/group sync.",
    ),
    _rule(
        "downstream-timeout",
        "Downstream service timeouts / connection failures",
        "medium",
        r"SocketTimeoutException|Read timed out|Connection reset|ConnectTimeoutException"
        r"|Connection refused|connect timed out",
        "An external system is slow or unreachable. Set explicit timeouts, add retries with backoff "
        "and a circuit breaker, and check egress/network configuration.",
        extract=r"(https?://[^\s/'\"]+)",
    ),
)


def match_rule(level: str, text: str) -> Optional[Rule]:
    for rule in RULES:
        if rule.applies_to(level) and rule.pattern.search(text):
            return rule
    return None
