"""Pluggable artifact extraction utilities."""

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

try:
    import olefile
    OLEFILE_AVAILABLE = True
except ImportError:
    OLEFILE_AVAILABLE = False

try:
    import PyPDF2
    PYPDF2_AVAILABLE = True
except ImportError:
    PYPDF2_AVAILABLE = False


def extract_pe_artifacts(file_path: str) -> dict:
    """Extract PE file metadata and artifacts."""
    result = {'available': PEFILE_AVAILABLE, 'sections': [], 'imports': [], 'exports': [], 'error': None}
    if not PEFILE_AVAILABLE:
        result['error'] = 'pefile not installed'
        return result
    try:
        pe = pefile.PE(file_path)
        for section in pe.sections:
            result['sections'].append({
                'name': section.Name.decode('utf-8', errors='replace').rstrip('\x00'),
                'virtual_address': hex(section.VirtualAddress),
                'size': section.SizeOfRawData,
                'entropy': section.get_entropy(),
            })
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode('utf-8', errors='replace')
                funcs = []
                for imp in entry.imports:
                    if imp.name:
                        funcs.append(imp.name.decode('utf-8', errors='replace'))
                result['imports'].append({'dll': dll, 'functions': funcs[:20]})
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    result['exports'].append(exp.name.decode('utf-8', errors='replace'))
        result['machine_type'] = hex(pe.FILE_HEADER.Machine)
        result['timestamp'] = pe.FILE_HEADER.TimeDateStamp
        result['compile_time'] = pe.FILE_HEADER.TimeDateStamp
    except Exception as e:
        result['error'] = str(e)
    return result


def extract_pdf_artifacts(file_path: str) -> dict:
    """Extract PDF metadata and artifacts."""
    result = {'available': PYPDF2_AVAILABLE, 'pages': 0, 'metadata': {}, 'links': [], 'error': None}
    if not PYPDF2_AVAILABLE:
        result['error'] = 'PyPDF2 not installed'
        return result
    try:
        with open(file_path, 'rb') as f:
            reader = PyPDF2.PdfReader(f)
            result['pages'] = len(reader.pages)
            if reader.metadata:
                for k, v in reader.metadata.items():
                    result['metadata'][str(k)] = str(v)
    except Exception as e:
        result['error'] = str(e)
    return result


def extract_office_artifacts(file_path: str) -> dict:
    """Extract Office document artifacts using olefile."""
    result = {'available': OLEFILE_AVAILABLE, 'streams': [], 'metadata': {}, 'error': None}
    if not OLEFILE_AVAILABLE:
        result['error'] = 'olefile not installed'
        return result
    try:
        if olefile.isOleFile(file_path):
            ole = olefile.OleFileIO(file_path)
            result['streams'] = ole.listdir()
            meta = ole.get_metadata()
            result['metadata'] = {
                'author': str(meta.author) if meta.author else '',
                'last_saved_by': str(meta.last_saved_by) if meta.last_saved_by else '',
                'title': str(meta.title) if meta.title else '',
                'subject': str(meta.subject) if meta.subject else '',
            }
            ole.close()
    except Exception as e:
        result['error'] = str(e)
    return result


def run_all_extractors(file_path: str, file_type: str) -> dict:
    """Run all relevant extractors for a file type."""
    results = {}
    file_type_upper = file_type.upper() if file_type else ''
    if any(t in file_type_upper for t in ('PE', 'EXE', 'DLL', 'EXECUTABLE')):
        results['pe'] = extract_pe_artifacts(file_path)
    if 'PDF' in file_type_upper:
        results['pdf'] = extract_pdf_artifacts(file_path)
    if any(t in file_type_upper for t in ('OLE', 'DOC', 'XLS', 'PPT', 'MSI', 'OFFICE')):
        results['office'] = extract_office_artifacts(file_path)
    return results
