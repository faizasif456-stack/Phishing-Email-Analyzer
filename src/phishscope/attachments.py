import hashlib
import io
import zipfile
from dataclasses import dataclass, field

from .scoring import Finding

EXECUTABLE = {
    "exe", "scr", "com", "pif", "cpl", "dll", "msi", "msp", "bat", "cmd", "ps1", "psm1", "vbs", "vbe",
    "js", "jse", "wsf", "wsh", "hta", "jar", "lnk", "reg", "chm", "scf", "iso", "img", "vhd", "vhdx",
    "one", "appx", "msix", "application", "gadget", "inf", "sct", "url",
}
MACRO_OFFICE = {"docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "sldm"}
HTML_LIKE = {"html", "htm", "shtml", "xhtml", "svg", "mht", "mhtml"}
ARCHIVES = {"zip", "rar", "7z", "gz", "tgz", "tar", "ace", "cab", "arj", "xz", "bz2"}
EXECUTABLE_MIME = {
    "application/octet-stream", "application/x-msdownload", "application/x-dosexec",
    "application/vnd.microsoft.portable-executable", "application/x-msdos-program", "application/x-executable",
}
DOCUMENTS = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "txt", "csv", "jpg", "jpeg", "png", "gif"}

SIGNATURES = [
    (b"MZ", "exe"),
    (b"%PDF", "pdf"),
    (b"PK\x03\x04", "zip"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),
    (b"\x7fELF", "elf"),
    (b"Rar!\x1a\x07", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x1f\x8b", "gzip"),
    (b"\x89PNG", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"GIF8", "gif"),
    (b"{\\rtf", "rtf"),
]

EXPECTED = {
    "pdf": {"pdf"},
    "docx": {"zip"}, "xlsx": {"zip"}, "pptx": {"zip"}, "zip": {"zip"},
    "docm": {"zip"}, "xlsm": {"zip"}, "pptm": {"zip"},
    "doc": {"ole", "rtf"}, "xls": {"ole"}, "ppt": {"ole"}, "msg": {"ole"},
    "png": {"png"}, "jpg": {"jpeg"}, "jpeg": {"jpeg"}, "gif": {"gif"},
    "rtf": {"rtf"}, "rar": {"rar"}, "7z": {"7z"}, "gz": {"gzip"},
    "txt": {"text"}, "csv": {"text"},
}


@dataclass
class AttachmentInfo:
    filename: str
    content_type: str
    size: int
    md5: str
    sha1: str
    sha256: str
    detected_type: str
    flags: list = field(default_factory=list)
    archive_members: list = field(default_factory=list)
    reputation: dict | None = None


def detect_type(data):
    for magic, kind in SIGNATURES:
        if data.startswith(magic):
            return kind
    if data[0x8001:0x8006] == b"CD001":
        return "iso"
    head = data[:1024].lstrip().lower()
    if head.startswith((b"<!doctype html", b"<html", b"<svg", b"<?xml")) or b"<script" in head:
        return "html"
    if data and all(32 <= b < 127 or b in (9, 10, 13) for b in data[:512]):
        return "text"
    return "unknown"


def extensions(filename):
    name = filename.lower().strip().rstrip(".")
    return name.split(".")[1:] if "." in name else []


def last_extension(filename):
    exts = extensions(filename)
    return exts[-1] if exts else ""


def _zip_contents(data):
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            return [i.filename for i in infos], any(i.flag_bits & 0x1 for i in infos)
    except (zipfile.BadZipFile, ValueError, OSError):
        return None, False


def inspect(attachment):
    data = attachment.data
    filename = attachment.filename
    exts = extensions(filename)
    ext = last_extension(filename)
    detected = detect_type(data)
    flags = []
    members = []

    if "‮" in filename:
        flags.append(("Filename uses a right-to-left override character to fake its extension", 30))
    if ext in EXECUTABLE:
        flags.append((f"Executable or script attachment (.{ext})", 35))
    elif ext in MACRO_OFFICE:
        flags.append((f"Macro-enabled Office document (.{ext})", 25))
    elif ext in HTML_LIKE:
        flags.append((f"HTML/SVG attachment (.{ext}) can host a fake login page or smuggle files", 20))
    if len(exts) >= 2 and exts[-2] in DOCUMENTS and ext not in DOCUMENTS:
        flags.append((f"Double extension .{exts[-2]}.{ext} disguises the real file type", 20))

    if detected == "exe" and ext not in EXECUTABLE:
        flags.append((f"File claims to be .{ext or 'unknown'} but is a Windows executable", 35))
    elif ext in EXPECTED and detected not in EXPECTED[ext] and detected != "unknown":
        flags.append((f"Content is {detected}, not what the .{ext} extension says", 15))
    if detected == "exe" and attachment.content_type not in EXECUTABLE_MIME:
        flags.append((f"Declared as {attachment.content_type} but contains a Windows executable", 15))
    if detected == "html" and ext not in HTML_LIKE:
        flags.append(("Attachment contains HTML disguised under another extension", 20))

    if detected == "zip":
        names, encrypted = _zip_contents(data)
        if names is not None:
            members = names
            if any(n.lower().endswith("vbaproject.bin") for n in names) and ext not in MACRO_OFFICE:
                flags.append(("Office file contains VBA macros", 25))
            if encrypted:
                flags.append(("Password-protected archive, which hides its contents from scanners", 15))
            risky = [n for n in names if last_extension(n.rsplit("/", 1)[-1]) in EXECUTABLE]
            if risky:
                flags.append((f"Archive contains executable files: {', '.join(risky[:5])}", 35))
    elif ext in ARCHIVES:
        flags.append((f"Archive attachment (.{ext}) that cannot be inspected", 8))

    info = AttachmentInfo(
        filename=filename,
        content_type=attachment.content_type,
        size=len(data),
        md5=hashlib.md5(data).hexdigest(),
        sha1=hashlib.sha1(data).hexdigest(),
        sha256=hashlib.sha256(data).hexdigest(),
        detected_type=detected,
        archive_members=members,
    )
    return info, flags


def analyze_attachments(attachments):
    infos, findings = [], []
    for attachment in attachments:
        info, flags = inspect(attachment)
        for message, points in flags:
            info.flags.append(message)
            findings.append(Finding("attachments", f"{info.filename}: {message}", points, floor=45 if points >= 35 else 0))
        infos.append(info)
    return infos, findings
