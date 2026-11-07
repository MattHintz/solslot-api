"""Bounded type checks for private spreadsheet originals; never execute them."""
from io import BytesIO
from pathlib import PurePosixPath
from xml.etree import ElementTree
from zipfile import BadZipFile, ZipFile
from zlib import error as ZlibError

XLSX_MIME = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
WORKBOOK_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"


def is_private_workbook(payload: bytes) -> bool:
    if not payload.startswith(b"PK\x03\x04"):
        return False
    try:
        with ZipFile(BytesIO(payload)) as archive:
            entries = archive.infolist()
            names = [item.filename for item in entries]
            if (len(entries) > 2048 or len(set(names)) != len(names)
                    or sum(item.file_size for item in entries) > 32 * 1024 * 1024
                    or not {"[Content_Types].xml", "xl/workbook.xml"}.issubset(names)):
                return False
            for item in entries:
                path = PurePosixPath(item.filename)
                if (path.is_absolute() or ".." in path.parts or "\\" in item.filename
                        or item.flag_bits & 1 or item.file_size > 8 * 1024 * 1024
                        or (item.external_attr >> 16) & 0o170000 == 0o120000
                        or "vbaproject" in item.filename.lower()
                        or item.filename.lower().startswith(("xl/embeddings/", "xl/externallinks/"))):
                    return False
            content = archive.read("[Content_Types].xml")
            workbook = archive.read("xl/workbook.xml")
            if len(content) > 256 * 1024 or len(workbook) > 2 * 1024 * 1024:
                return False
            if any(marker in data.upper() for marker in (b"<!DOCTYPE", b"<!ENTITY")
                   for data in (content, workbook)):
                return False
            types = ElementTree.fromstring(content)
            if types.tag != "{http://schemas.openxmlformats.org/package/2006/content-types}Types":
                return False
            for part in types:
                if "macro" in part.get("ContentType", "").lower():
                    return False
            # Package content types may specify the workbook via an Override
            # or via the Default for XML, as the reviewed budget exporter does.
            workbook_types = [part.get("ContentType") for part in types
                              if part.tag.endswith("}Override") and part.get("PartName") == "/xl/workbook.xml"]
            if not workbook_types:
                workbook_types = [part.get("ContentType") for part in types
                                  if part.tag.endswith("}Default") and part.get("Extension") == "xml"]
            if workbook_types != [WORKBOOK_TYPE]:
                return False
            root = ElementTree.fromstring(workbook)
            return root.tag == "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}workbook"
    except (BadZipFile, KeyError, ValueError, RuntimeError, NotImplementedError,
            OSError, ZlibError, ElementTree.ParseError):
        return False
