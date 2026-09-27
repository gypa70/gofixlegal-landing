"""Kontrola statického webu gofixlegal.com. Exit 1 při nálezu."""

from __future__ import annotations

import re
import sys
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN = (
    "zertifiziert",
    "verifiziert",
    "Zertifikat",
    "certified",
    "verified",
    "C2PA-konform",
    "C2PA conformant",
    "Midjourney",
    "certifikováno",
    "certifikovaný",
    "ověřeno",
    "garance souladu",
    "zaručujeme",
)
SENTENCES = (
    "Art. 50 EU AI Act gilt seit 2. August 2026.",
    "Ab 2. Dezember 2026 müssen auch bereits verfügbare Bildgeneratoren maschinenlesbare Herkunftsmarkierungen einbetten (Pflicht der Anbieter der Generatoren).",
    "Deepfakes müssen sichtbar gekennzeichnet werden.",
)
IMPRESSUM_BITS = (
    "FinalEdge s.r.o.",
    "Korunní 2569/108",
    "Vinohrady",
    "101 00 Praha 10",
    "19181761",
    "Libor Sup",
    "libor@gofixlegal.com",
)
CTA = "mailto:libor@gofixlegal.com?subject=Testlauf%20KI-Bild-Check"
ANALYTICS = (
    "fonts.googleapis.com",
    "googletagmanager.com",
    "google-analytics.com",
    "gtag(",
    "plausible.io",
    "matomo",
    "hotjar",
    "facebook.net",
    "cookiebot",
    "onetrust",
    "document.cookie",
)
LOCAL = {
    "/": ROOT / "index.html",
    "/en/": ROOT / "en" / "index.html",
    "/index.html": ROOT / "index.html",
    "/impressum.html": ROOT / "impressum.html",
    "/datenschutz.html": ROOT / "datenschutz.html",
    "/en/index.html": ROOT / "en" / "index.html",
    "/en/legal-notice.html": ROOT / "en" / "legal-notice.html",
    "/en/privacy.html": ROOT / "en" / "privacy.html",
    "/cs/": ROOT / "cs" / "index.html",
    "/cs/index.html": ROOT / "cs" / "index.html",
    "/cs/impressum.html": ROOT / "cs" / "impressum.html",
    "/cs/datenschutz.html": ROOT / "cs" / "datenschutz.html",
    "/assets/styles.css": ROOT / "assets" / "styles.css",
}


class _Links(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []
        self.scripts = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "script":
            self.scripts += 1
        for key, value in attrs:
            if key in {"href", "src"} and value:
                self.hrefs.append(value)


def _text(html: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", html)).strip()


def _local_target(href: str) -> Path | None:
    path = href.split("#", 1)[0].split("?", 1)[0]
    if path.startswith("mailto:") or path.startswith("#"):
        return None
    if path.startswith("https://gofixlegal.com"):
        path = path[len("https://gofixlegal.com") :] or "/"
    if path in LOCAL:
        return LOCAL[path]
    if path.startswith("/"):
        return ROOT / path.lstrip("/")
    return None


def main() -> int:
    findings: list[str] = []
    files = [
        p
        for p in ROOT.rglob("*")
        if p.is_file()
        and p.suffix in {".html", ".css"}
        and "_screenshots" not in p.parts
        and ".git" not in p.parts
    ]
    blob_parts: list[str] = []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        rel = path.relative_to(ROOT).as_posix()
        blob_parts.append(text)
        for word in FORBIDDEN:
            if word in text:
                findings.append(f"{rel}: zakázané slovo {word}")
        low = text.lower()
        if "<script" in low:
            findings.append(f"{rel}: obsahuje <script>")
        for needle in ANALYTICS:
            if needle.lower() in low:
                findings.append(f"{rel}: externí zdroj {needle}")
        if path.suffix == ".html":
            parser = _Links()
            parser.feed(text)
            if parser.scripts:
                findings.append(f"{rel}: <script> v HTML")
            for href in parser.hrefs:
                if href.startswith(("http://", "https://")) and "gofixlegal.com" not in href:
                    findings.append(f"{rel}: externí odkaz {href}")
                    continue
                target = _local_target(href)
                if target is not None and not target.is_file():
                    findings.append(f"{rel}: chybí cíl {href}")
    joined = "\n".join(blob_parts)
    visible = _text(joined)
    for sentence in SENTENCES:
        if sentence not in visible:
            findings.append(f"chybí věta: {sentence}")
    impressum = (ROOT / "impressum.html").read_text(encoding="utf-8")
    for bit in IMPRESSUM_BITS:
        if bit not in impressum:
            findings.append(f"impressum.html neobsahuje {bit}")
    if CTA not in joined:
        findings.append(f"chybí CTA {CTA}")
    if findings:
        print("\n".join(findings))
        return 1
    print("bez nálezu")
    return 0


if __name__ == "__main__":
    sys.exit(main())
