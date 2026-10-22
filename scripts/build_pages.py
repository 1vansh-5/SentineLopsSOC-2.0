"""Package only the public sample dashboard for GitHub Pages."""
from pathlib import Path
import shutil


def build(root: Path) -> Path:
    source = root / 'app' / 'dashboard'
    output = root / '_site'
    html = (source / 'index.html').read_text(encoding='utf-8')
    html = html.replace('/dashboard/assets/', './assets/')
    html = html.replace('href="/dashboard"', 'href="./"')
    html = html.replace('href="/docs"', 'href="https://github.com/1vansh-5/SentineLopsSOC-2.0#api-and-authentication"')
    html = html.replace('id="session-button"', 'id="session-button" disabled title="Analyst connections require the local Python server"')
    html = html.replace('</head>', '<meta name="sentinelops-hosting" content="Read-only sample; analyst actions require the Python server">\n</head>')
    assets = output / 'assets'
    assets.mkdir(parents=True, exist_ok=True)
    for name in ('dashboard.css', 'sample.js', 'dashboard.js'):
        shutil.copyfile(source / name, assets / name)
    (output / 'index.html').write_text(html, encoding='utf-8')
    (output / '.nojekyll').touch()
    return output


if __name__ == '__main__':
    build(Path(__file__).resolve().parents[1])

