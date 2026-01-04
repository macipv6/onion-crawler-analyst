# plugins/template_fp.py
import hashlib
from bs4 import BeautifulSoup

def template_fingerprint(html: str) -> str | None:
    if not html:
        return None
    soup = BeautifulSoup(html, "html.parser")

    tags = {}
    classes = {}
    for tag in soup.find_all(True):
        name = tag.name.lower()
        tags[name] = tags.get(name, 0) + 1
        for cls in tag.get("class", []):
            cls = str(cls).strip().lower()
            if not cls:
                continue
            classes[cls] = classes.get(cls, 0) + 1

    # Canonical representation aus häufigsten Tags/Klassen
    top_tags = sorted(tags.items(), key=lambda x: (-x[1], x[0]))[:30]
    top_classes = sorted(classes.items(), key=lambda x: (-x[1], x[0]))[:50]

    blob = "TAGS:" + ";".join(f"{k}:{v}" for k, v in top_tags) + "|CLS:" + ";".join(
        f"{k}:{v}" for k, v in top_classes
    )
    return hashlib.sha256(blob.encode("utf-8", "ignore")).hexdigest().upper()
