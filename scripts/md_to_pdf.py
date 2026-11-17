import os
import sys
import subprocess
import markdown

def convert_md_to_pdf(md_path, pdf_path, title="ARPShield - Documentación Oficial"):
    with open(md_path, "r", encoding="utf-8") as f:
        md_content = f.read()

    # Convert Markdown to HTML
    html_body = markdown.markdown(
        md_content,
        extensions=["tables", "fenced_code", "toc", "sane_lists"]
    )

    # Professional CSS for Print / PDF
    css = """
    @page {
        size: A4;
        margin: 20mm 15mm 20mm 15mm;
        @bottom-right {
            content: "Página " counter(page);
            font-size: 9pt;
            color: #718096;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
    }

    body {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
        font-size: 10.5pt;
        line-height: 1.6;
        color: #1a202c;
        background-color: #ffffff;
        margin: 0;
        padding: 0;
    }

    h1, h2, h3, h4, h5, h6 {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
        color: #0f172a;
        font-weight: 700;
        margin-top: 1.6em;
        margin-bottom: 0.6em;
        page-break-after: avoid;
    }

    h1 {
        font-size: 20pt;
        border-bottom: 2px solid #3b82f6;
        padding-bottom: 8px;
        margin-top: 0;
        color: #1e3a8a;
    }

    h2 {
        font-size: 15pt;
        border-bottom: 1px solid #e2e8f0;
        padding-bottom: 6px;
        margin-top: 2em;
        color: #1e40af;
        page-break-before: auto;
    }

    h3 {
        font-size: 12pt;
        color: #1e293b;
    }

    h4 {
        font-size: 11pt;
        color: #334155;
    }

    p, li {
        color: #334155;
    }

    a {
        color: #2563eb;
        text-decoration: none;
    }

    table {
        width: 100%;
        border-collapse: collapse;
        margin: 1.2em 0;
        font-size: 9.5pt;
        page-break-inside: avoid;
    }

    th, td {
        border: 1px solid #cbd5e1;
        padding: 7px 10px;
        text-align: left;
    }

    th {
        background-color: #f1f5f9;
        color: #0f172a;
        font-weight: 600;
    }

    tr:nth-child(even) td {
        background-color: #f8fafc;
    }

    code {
        font-family: Consolas, Monaco, "Courier New", Courier, monospace;
        font-size: 9pt;
        background-color: #f1f5f9;
        color: #0f172a;
        padding: 2px 5px;
        border-radius: 4px;
        border: 1px solid #e2e8f0;
    }

    pre {
        background-color: #0f172a;
        color: #f8fafc;
        padding: 12px 16px;
        border-radius: 6px;
        overflow-x: auto;
        font-size: 8.5pt;
        line-height: 1.45;
        page-break-inside: avoid;
        margin: 1.2em 0;
    }

    pre code {
        background-color: transparent;
        color: #f8fafc;
        padding: 0;
        border: none;
        font-size: 8.5pt;
    }

    blockquote {
        margin: 1.2em 0;
        padding: 8px 16px;
        border-left: 4px solid #3b82f6;
        background-color: #eff6ff;
        color: #1e40af;
        border-radius: 0 4px 4px 0;
    }

    blockquote p {
        margin: 0;
        color: #1e40af;
    }

    hr {
        border: 0;
        height: 1px;
        background: #e2e8f0;
        margin: 2em 0;
    }

    ul, ol {
        padding-left: 24px;
        margin: 0.8em 0;
    }

    li {
        margin-bottom: 4px;
    }

    .cover-badge {
        display: inline-block;
        padding: 4px 10px;
        background-color: #e0f2fe;
        color: #0369a1;
        border-radius: 9999px;
        font-size: 8.5pt;
        font-weight: 600;
        margin-bottom: 12px;
    }
    """

    full_html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>{title}</title>
    <style>
{css}
    </style>
</head>
<body>
{html_body}
</body>
</html>
"""

    temp_html_path = md_path.replace(".md", "_temp.html")
    with open(temp_html_path, "w", encoding="utf-8") as f:
        f.write(full_html)

    # Call msedge headless to print to PDF
    edge_path = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
    if not os.path.exists(edge_path):
        edge_path = r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"

    abs_temp_html = os.path.abspath(temp_html_path)
    abs_pdf_path = os.path.abspath(pdf_path)

    cmd = [
        edge_path,
        "--headless",
        "--disable-gpu",
        "--no-pdf-header-footer",
        f"--print-to-pdf={abs_pdf_path}",
        f"file:///{abs_temp_html.replace(os.sep, '/')}"
    ]

    print(f"Generating PDF from {md_path} -> {pdf_path}...")
    res = subprocess.run(cmd, capture_output=True, text=True)
    
    if os.path.exists(temp_html_path):
        os.remove(temp_html_path)

    if res.returncode == 0 and os.path.exists(abs_pdf_path):
        size_kb = os.path.getsize(abs_pdf_path) / 1024
        print(f"Success! PDF generated at {pdf_path} ({size_kb:.2f} KB)")
        return True
    else:
        print(f"Error: {res.stderr}")
        return False

if __name__ == "__main__":
    docs_dir = "docs"
    # Convert official documentation
    md_file = os.path.join(docs_dir, "documentacion_oficial_arpshield.md")
    pdf_file = os.path.join(docs_dir, "documentacion_oficial_arpshield.pdf")
    convert_md_to_pdf(md_file, pdf_file, "ARPShield - Documentación Oficial y Manual de Uso")

    # Also create manual_de_usuario.pdf specifically
    user_manual_pdf = os.path.join(docs_dir, "manual_de_uso_arpshield.pdf")
    import shutil
    shutil.copyfile(pdf_file, user_manual_pdf)
    print(f"Copied to {user_manual_pdf}")
