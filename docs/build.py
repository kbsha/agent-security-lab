"""Wrap docs/app.html (the browser-only demo) into docs/index.html for GitHub Pages.

    python3 docs/build.py
"""

from pathlib import Path

here = Path(__file__).parent
body = (here / "app.html").read_text()
page = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<!-- Generated from app.html by build.py. Edit app.html, then rebuild. -->
</head>
<body>
{body}
</body>
</html>
"""
(here / "index.html").write_text(page)
print("wrote", here / "index.html")
