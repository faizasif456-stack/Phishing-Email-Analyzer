import io
import zipfile

from phishscope.attachments import detect_type, inspect
from phishscope.parser import Attachment

MZ = b"MZ" + b"\x00" * 200


def flags(filename, data, mime="application/octet-stream"):
    info, found = inspect(Attachment(filename, mime, data))
    return info, [message for message, _ in found]


def make_zip(files, encrypted=False):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, content in files.items():
            z.writestr(name, content)
    data = bytearray(buf.getvalue())
    if encrypted:
        data[6] |= 0x1
        central = data.find(b"PK\x01\x02")
        data[central + 8] |= 0x1
    return bytes(data)


def test_detect_type():
    assert detect_type(MZ) == "exe"
    assert detect_type(b"%PDF-1.7\n") == "pdf"
    assert detect_type(make_zip({"a.txt": "x"})) == "zip"
    assert detect_type(b"<!DOCTYPE html><html>") == "html"
    assert detect_type(b"plain text\n") == "text"


def test_clean_pdf():
    info, found = flags("report.pdf", b"%PDF-1.7 hello", "application/pdf")
    assert found == []
    assert len(info.sha256) == 64 and len(info.md5) == 32


def test_hashes_match():
    import hashlib
    info, _ = flags("a.txt", b"hello", "text/plain")
    assert info.sha256 == hashlib.sha256(b"hello").hexdigest()


def test_executable_double_extension():
    _, found = flags("invoice.pdf.exe", MZ, "application/pdf")
    assert any("Executable" in f for f in found)
    assert any("Double extension" in f for f in found)
    assert any("Declared as application/pdf" in f for f in found)


def test_disguised_executable():
    _, found = flags("invoice.pdf", MZ, "application/pdf")
    assert any("is a Windows executable" in f for f in found)


def test_rtl_override():
    _, found = flags("invoice‮fdp.exe", MZ)
    assert any("right-to-left" in f for f in found)


def test_macro_document():
    _, found = flags("form.docm", make_zip({"word/vbaProject.bin": "x"}))
    assert any("Macro-enabled" in f for f in found)


def test_macros_hidden_in_docx():
    _, found = flags("form.docx", make_zip({"word/document.xml": "x", "word/vbaProject.bin": "x"}))
    assert any("contains VBA macros" in f for f in found)


def test_archive_with_script():
    info, found = flags("docs.zip", make_zip({"docs/readme.txt": "x", "docs/run.js": "x"}))
    assert info.archive_members == ["docs/readme.txt", "docs/run.js"]
    assert any("docs/run.js" in f for f in found)


def test_encrypted_archive():
    _, found = flags("secure.zip", make_zip({"a.pdf": "x"}, encrypted=True))
    assert any("Password-protected" in f for f in found)


def test_html_attachment():
    _, found = flags("login.html", b"<html><form><input type=password></form></html>", "text/html")
    assert any("HTML/SVG attachment" in f for f in found)
