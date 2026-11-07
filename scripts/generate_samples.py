#!/usr/bin/env python3
"""Generate synthetic AEM error.log and request.log files for demos and tests.

The logs describe a fictional site (``/content/mysite``) built from the public AEM Project
Archetype. They contain no real customer data. Output is deterministic (fixed seed).

    python scripts/generate_samples.py            # writes samples/error.log and samples/request.log
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta
from pathlib import Path

SEED = 42
START = datetime(2026, 11, 2, 8, 0, 0)
HOURS = 12
OUT = Path(__file__).resolve().parent.parent / "samples"

PAGES = [
    "/content/mysite/us/en.html",
    "/content/mysite/us/en/products.html",
    "/content/mysite/us/en/about-us.html",
    "/content/mysite/us/en/contact.html",
    "/content/mysite/ca/fr.html",
] + [f"/content/mysite/us/en/blog/post-{n}.html" for n in range(1, 31)]
STATIC = [
    "/etc.clientlibs/mysite/clientlibs/clientlib-site.lc-8a1f2c3d-lc.min.js",
    "/etc.clientlibs/mysite/clientlibs/clientlib-site.lc-4b9e7d11-lc.min.css",
    "/etc.clientlibs/mysite/clientlibs/clientlib-base.lc-77c2d0aa-lc.min.js",
]
ASSETS = [
    f"/content/dam/mysite/images/hero-{n}.jpg/_jcr_content/renditions/cq5dam.web.1280.1280.jpeg"
    for n in range(1, 13)
]
AUTHORS = ["jdoe", "asmith", "mlee", "rpatel", "kchen", "tnguyen"]
INFO_MESSAGES = [
    ("org.apache.sling.audit.osgi.installer", "Installed configuration org.apache.sling.commons.log.LogManager"),
    ("com.day.cq.replication.impl.ReplicatorImpl", "Setting up replication with options [type=ACTIVATE, path=/content/mysite/us/en/blog]"),
    ("org.apache.jackrabbit.oak.plugins.index.IndexUpdate", "[async] Reindexing will be performed for following indexes: []"),
    ("com.adobe.granite.workflow.core.WorkflowSessionImpl", "Workflow started: /var/workflow/models/request_for_activation"),
    ("org.apache.sling.event.impl.jobs.queues.JobQueueImpl", "Starting job queue Granite Workflow Queue"),
    ("com.mysite.core.schedulers.SimpleScheduledTask", "SimpleScheduledTask is now running, myParameter='Hello'"),
    ("org.apache.jackrabbit.oak.plugins.index.AsyncIndexUpdate", "[async] AsyncIndex update run completed in 154.2 ms. Indexed 12 nodes"),
    ("com.day.cq.dam.core.impl.servlet.HealthCheckServlet", "Health check completed in 22ms"),
]


def thread(rng: random.Random, ts: datetime, url: str | None = None) -> str:
    if url:
        return f"[0:0:0:0:0:0:0:1 [{int(ts.timestamp() * 1000)}] GET {url} HTTP/1.1]"
    return f"[qtp1795960102-{rng.randint(100, 999)}]"


def error_line(ts: datetime, level: str, thr: str, logger: str, message: str) -> str:
    return f"{ts:%d.%m.%Y %H:%M:%S}.{ts.microsecond // 1000:03d} *{level}* {thr} {logger} {message}"


def random_time(rng: random.Random, start_hour: float = 0, end_hour: float = HOURS) -> datetime:
    return START + timedelta(seconds=rng.uniform(start_hour * 3600, end_hour * 3600))


def build_error_log(rng: random.Random) -> list[tuple[datetime, list[str]]]:
    events: list[tuple[datetime, list[str]]] = []

    def add(ts, level, logger, message, stack=(), url=None):
        events.append((ts, [error_line(ts, level, thread(rng, ts, url), logger, message), *stack]))

    for _ in range(2600):
        logger, message = rng.choice(INFO_MESSAGES)
        add(random_time(rng), "INFO", logger, message)

    add(START + timedelta(seconds=41), "ERROR", "com.mysite.core",
        "bundle com.mysite.core:1.0.0.SNAPSHOT (583)[com.mysite.core.schedulers.ContentSyncScheduler(2134)] : "
        "The activate method has thrown an exception",
        ["java.lang.IllegalArgumentException: Scheduler expression must not be empty",
         "\tat com.mysite.core.schedulers.ContentSyncScheduler.activate(ContentSyncScheduler.java:48)",
         "\tat java.base/jdk.internal.reflect.NativeMethodAccessorImpl.invoke0(Native Method)"])

    for _ in range(46):
        ts = random_time(rng, 2, 7) if rng.random() < 0.7 else random_time(rng)
        page = rng.choice(PAGES[5:])
        add(ts, "ERROR", "org.apache.sling.engine.impl.SlingRequestProcessorImpl",
            f"service: Uncaught SlingException {page}",
            ["org.apache.sling.scripting.sightly.SightlyException: Identifier com.mysite.core.models.ArticleModel "
             "cannot be correctly instantiated by the Use API",
             "\tat org.apache.sling.scripting.sightly.impl.engine.extension.use.UseRuntimeExtension.call(UseRuntimeExtension.java:73)",
             "Caused by: java.lang.NullPointerException: Cannot invoke \"String.trim()\" because \"this.author\" is null",
             "\tat com.mysite.core.models.ArticleModel.getAuthorName(ArticleModel.java:61)",
             "\tat com.mysite.core.models.ArticleModel.init(ArticleModel.java:44)",
             "\t... 182 common frames omitted"], url=page)

    for _ in range(31):
        author = rng.choice(AUTHORS)
        nodes = rng.choice([10000, 20000, 30000, 40000])
        add(random_time(rng), "WARN", "org.apache.jackrabbit.oak.plugins.index.Cursors$TraversingCursor",
            f"Traversed {nodes} nodes with filter Filter(query=SELECT * FROM [cq:Page] AS s WHERE "
            f"ISDESCENDANTNODE(s, [/content/mysite]) AND s.[jcr:content/author] = '{author}', "
            "path=/content/mysite//*, property=[jcr:content/author=[" + author + "]]); "
            "consider creating an index or changing the query", url="/content/mysite/us/en/search.html")
    for _ in range(9):
        add(random_time(rng), "WARN", "org.apache.jackrabbit.oak.plugins.index.Cursors$TraversingCursor",
            "Traversed 10000 nodes with filter Filter(query=SELECT * FROM [dam:Asset] WHERE "
            "[jcr:content/metadata/dc:format] = 'image/jpeg' ORDER BY [jcr:created] DESC, path=*); "
            "consider creating an index or changing the query")
    for _ in range(2):
        add(random_time(rng, 9, 10), "ERROR", "org.apache.jackrabbit.oak.query.FilterIterators",
            "The query read or traversed more than 100000 nodes. To avoid affecting other tasks, processing was stopped.",
            url="/content/mysite/us/en/search.html")

    for _ in range(17):
        add(random_time(rng), "WARN", "org.apache.sling.resourceresolver.impl.CommonResourceResolverFactoryImpl",
            "Unclosed ResourceResolver was created here: ",
            ["java.lang.Exception: Opening Stacktrace",
             "\tat org.apache.sling.resourceresolver.impl.ResourceResolverImpl.<init>(ResourceResolverImpl.java:115)",
             "\tat org.apache.sling.resourceresolver.impl.ResourceResolverFactoryImpl.getServiceResourceResolver(ResourceResolverFactoryImpl.java:89)",
             "\tat com.mysite.core.services.impl.TagSyncServiceImpl.run(TagSyncServiceImpl.java:72)"])

    for _ in range(4):
        add(random_time(rng, 0, 1), "ERROR", "com.mysite.core.services.impl.TagSyncServiceImpl",
            "Could not obtain service resource resolver",
            ["org.apache.sling.api.resource.LoginException: Cannot derive user name for bundle "
             "com.mysite.core [583] and sub service tag-sync-service",
             "\tat org.apache.sling.resourceresolver.impl.ResourceResolverFactoryImpl.getServiceResourceResolver(ResourceResolverFactoryImpl.java:80)"])

    for _ in range(7):
        add(random_time(rng, 5, 5.5), "ERROR", "com.day.cq.replication.impl.AgentManagerImpl",
            "Unable to process replication for /content/mysite/us/en/blog",
            ["com.day.cq.replication.ReplicationException: Failed to send request to publish: Connection refused",
             "\tat com.day.cq.replication.impl.transport.HTTPTransportHandler.deliver(HTTPTransportHandler.java:312)"])

    for _ in range(23):
        add(random_time(rng, 6, 8), "ERROR", "com.mysite.core.services.impl.WeatherApiClient",
            "Failed to fetch forecast from https://api.weather.example.com/v1/forecast",
            ["java.net.SocketTimeoutException: Read timed out",
             "\tat java.base/java.net.SocketInputStream.socketRead0(Native Method)",
             "\tat com.mysite.core.services.impl.WeatherApiClient.fetch(WeatherApiClient.java:88)"],
            url="/bin/mysite/weather")

    for _ in range(5):
        add(random_time(rng), "WARN", "org.apache.jackrabbit.oak.plugins.document.Commit",
            "OakState0001: Unresolved conflicts in /content/mysite/us/en/jcr:content",
            ["org.apache.jackrabbit.oak.api.CommitFailedException: OakState0001: Unresolved conflicts in "
             "/content/mysite/us/en/jcr:content"])

    for _ in range(3):
        add(random_time(rng, 10, 11), "WARN", "org.apache.jackrabbit.oak.plugins.index.AsyncIndexUpdate",
            "[async] The index update failed",
            ["org.apache.jackrabbit.oak.api.CommitFailedException: OakAsync0002: Missing index provider "
             "detected for type [lucene] on index [/oak:index/damAssetLucene]"])

    for _ in range(160):
        add(random_time(rng), "ERROR", "com.mysite.core.i18n.DictionaryLookup",
            f"Missing i18n dictionary for language fr_CA, key {rng.randint(1000, 9999)}")

    oom_ts = START + timedelta(hours=10, minutes=37, seconds=12)
    add(oom_ts, "ERROR", "org.apache.sling.engine.impl.SlingRequestProcessorImpl",
        "service: Uncaught Throwable",
        ["java.lang.OutOfMemoryError: Java heap space",
         "\tat java.base/java.util.Arrays.copyOf(Arrays.java:3537)",
         "\tat com.mysite.core.servlets.ExportServlet.doGet(ExportServlet.java:57)"],
        url="/bin/mysite/export.csv")

    events.sort(key=lambda event: event[0])
    return events


def build_request_log(rng: random.Random) -> list[tuple[datetime, int, str]]:
    lines: list[tuple[datetime, int, str]] = []
    order = 0

    def stamp(ts: datetime) -> str:
        return ts.strftime("%d/%b/%Y:%H:%M:%S +0000")

    for request_id in range(1, 4201):
        ts = random_time(rng)
        roll = rng.random()
        method, status, ctype = "GET", 200, "text/html"
        if roll < 0.40:
            url = rng.choice(PAGES)
            duration = int(rng.lognormvariate(4.3, 0.6))
            if url in PAGES[5:] and START + timedelta(hours=2) <= ts <= START + timedelta(hours=7) and rng.random() < 0.06:
                status = 500
        elif roll < 0.62:
            url = rng.choice(STATIC)
            ctype = "application/javascript" if url.endswith("js") else "text/css"
            duration = int(rng.lognormvariate(1.8, 0.5))
            if rng.random() < 0.3:
                status, ctype = 304, "-"
        elif roll < 0.80:
            url = rng.choice(ASSETS)
            ctype = "image/jpeg"
            duration = int(rng.lognormvariate(3.2, 0.7))
        elif roll < 0.88:
            url = f"/content/mysite/us/en/search.html?q={rng.choice(['shoes', 'returns', 'store', 'sale'])}&author={rng.choice(AUTHORS)}"
            duration = int(rng.lognormvariate(7.4, 0.5))
        elif roll < 0.93:
            url = "/bin/mysite/weather?city=vancouver"
            ctype = "application/json"
            duration = int(rng.lognormvariate(5.0, 0.4))
            if START + timedelta(hours=6) <= ts <= START + timedelta(hours=8) and rng.random() < 0.5:
                status, duration = 504, 10000 + rng.randint(0, 40)
        elif roll < 0.97:
            url = f"/content/mysite/us/en/old-page-{rng.randint(1, 40)}.html"
            status = 404
            duration = int(rng.lognormvariate(3.0, 0.4))
        else:
            method = "POST"
            url = "/content/mysite/us/en/contact/_jcr_content/root/form.form.html"
            status, ctype = 302, "-"
            duration = int(rng.lognormvariate(4.8, 0.4))
        duration = max(duration, 1)
        lines.append((ts, order, f"{stamp(ts)} [{request_id}] -> {method} {url} HTTP/1.1"))
        order += 1
        if request_id in (1807, 3311, 3312):
            continue  # simulate requests that never completed
        end = ts + timedelta(milliseconds=duration)
        lines.append((end, order, f"{stamp(end)} [{request_id}] <- {status} {ctype} {duration}ms"))
        order += 1

    lines.sort(key=lambda item: (item[0], item[1]))
    return lines


def main() -> None:
    rng = random.Random(SEED)
    OUT.mkdir(exist_ok=True)
    with open(OUT / "error.log", "w", encoding="utf-8") as fh:
        for _, event_lines in build_error_log(rng):
            fh.write("\n".join(event_lines) + "\n")
    with open(OUT / "request.log", "w", encoding="utf-8") as fh:
        for _, _, line in build_request_log(rng):
            fh.write(line + "\n")
    print(f"wrote {OUT / 'error.log'} and {OUT / 'request.log'}")


if __name__ == "__main__":
    main()
