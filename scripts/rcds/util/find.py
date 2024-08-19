from itertools import chain
from pathlib import Path
from typing import Dict, List, Optional

from .load import SUPPORTED_EXTENSIONS


def find_files(
    names: List[str],
    extensions: List[str],
    path: Optional[Path] = None,
    recurse: bool = True,
) -> Dict[str, Path]:
    if path is None:
        path = Path.cwd().resolve()
    foundNames = set(names)
    found = dict()
    dirList = chain([path], path.parents) if recurse else [path]
    for d in dirList:
        for f in filter(lambda f: f.is_file(), d.iterdir()):
            if f.suffix[1:] in extensions and f.stem in foundNames:
                found[f.stem] = f
                foundNames.remove(f.stem)
    return found


def find_cfgs(path: Optional[Path] = None) -> Dict[str, Path]:
    return find_files(["rcds", "challenge"], SUPPORTED_EXTENSIONS, path)
