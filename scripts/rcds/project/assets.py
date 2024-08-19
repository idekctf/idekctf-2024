import io
import json
import os
import pathlib
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    BinaryIO,
    ByteString,
    Callable,
    Dict,
    Iterable,
    Set,
    Tuple,
    Union,
    cast,
)
from warnings import warn

if TYPE_CHECKING:
    import rcds

    from .project import Project


File = Union[BinaryIO, Path, bytes]
"""
Something that the asset manager can interpret as a file (contents only)

Valid types:

- A :class:`pathlib.Path` object referring to a file that already exists on-disk

- Any :class:`typing.BinaryIO` object that is seekable

- A :class:`typing.ByteString` object containing the contents of the file (internally
  this is converted to a :class:`io.BytesIO`)
"""


def _is_valid_name(name: str):
    return (
        len(pathlib.PurePosixPath(name).parts) == 1
        and len(pathlib.PureWindowsPath(name).parts) == 1
    )


class AssetManagerTransaction:
    """
    A transaction within an :class:`AssetManagerContext`

    This class manages declarative transactional updates to a context, allowing you to
    declare the files that should exist in the context, the last time that file was
    modified, and a callable to run to get the file, should it be out-of-date in the
    cache. The transaction starts in a blank state; without adding anything by calling
    :meth:`add`, :meth:`commit` will clear the context. No actions are performed until
    :meth:`commit` is called.

    This classs is not meant to be constructed directly, use
    :meth:`AssetManagerContext.transaction`
    """

    _asset_manager_context: "AssetManagerContext"
    _is_active: bool

    @dataclass
    class _FileEntry:
        """
        :meta private:
        """

        mtime: float

        # Callable is wrapped in a tuple because otherwise, mypy thinks the field is a
        # class method (related to python/mypy#708)
        get_contents: Tuple[Callable[[], File]]

    _files: Dict[str, _FileEntry]

    def __init__(self, asset_manager_context: "AssetManagerContext"):
        """
        :meta private:
        """
        self._asset_manager_context = asset_manager_context
        self._is_active = True
        self._files = dict()

    def add(
        self, name: str, mtime: float, contents: Union[File, Callable[[], File]]
    ) -> None:
        """
        Add a file to the context

        :param str name: The name of the asset to add
        :param float mtime: The time the asset to add was modified
            (:attr:`os.stat_result.st_mtime`)
        :param contents: The contents of the file - this can either be the contents
            directly as a :const:`File`, or a thunk function that, when calls, returns
            the contents
        :type contents: :const:`File` or :obj:`Callable[[], File]`
        :raises RuntimeError: if the transaction has already been committed
        :raises ValueError: if the asset name is not valid
        """
        if not self._is_active:
            raise RuntimeError("This transaction has already been committed")
        self._asset_manager_context._assert_valid_name(name)
        get_contents: Callable[[], File]
        if callable(contents):
            get_contents = contents
        else:

            def get_contents() -> File:
                return cast(File, contents)

        self._files[name] = self._FileEntry(mtime=mtime, get_contents=(get_contents,))

    def add_file(self, name: str, file: Path):
        """
        Add an already-existing file on disk to the context

        This wraps :meth:`add`

        :param str name: The name of the asset to add
        :param Path file: The path to the asset on disk
        """
        if not file.is_file():
            raise ValueError(f"Provided file does not exist: '{str(file)}'")
        self.add(name, file.stat().st_mtime, lambda: file)

    def _create(self, fpath: Path, fentry: _FileEntry) -> None:
        """
        Create / overwrite the asset in the cache

        :meta private:
        """
        contents = fentry.get_contents[0]()
        if isinstance(contents, Path):
            if not contents.is_file():
                raise ValueError(f"Provided file does not exist: '{str(contents)}'")
            fpath.symlink_to(contents)
        else:
            if isinstance(contents, ByteString):
                contents = io.BytesIO(contents)
            assert isinstance(contents, io.IOBase)
            with fpath.open("wb") as ofd:
                shutil.copyfileobj(contents, ofd)
        os.utime(fpath, (fentry.mtime, fentry.mtime))

    def commit(self) -> None:
        """
        Commit the transaction.

        This transaction can no longer be used after :meth:`commit` is called.
        """
        self._is_active = False
        self._asset_manager_context._is_transaction_active = False
        files_to_delete = set(self._asset_manager_context.ls())
        for name, file_entry in self._files.items():
            fpath = self._asset_manager_context._get(name)
            try:
                files_to_delete.remove(name)
            except KeyError:
                pass
            if self._asset_manager_context.exists(name):
                cache_mtime = self._asset_manager_context.get_mtime(name)
                if not file_entry.mtime > cache_mtime:
                    continue
            self._create(fpath, file_entry)
            self._asset_manager_context._add(name, force=True)
        for name in files_to_delete:
            fpath = self._asset_manager_context.get(name)
            fpath.unlink()
            self._asset_manager_context._rm(name)
        self._asset_manager_context.sync(check=True)


class AssetManagerContext:
    """
    A subcontext within an :class:`AssetManager`

    Represents a namespace within the :class:`AssetManager`, essentially a
    subdirectory. The context holds assets for a challenge with the same id

    This class is not meant to be constructed directly, use
    :meth:`AssetManager.create_context`
    """

    _asset_manager: "AssetManager"
    _name: str
    _root: Path
    _files: Set[str]
    _files_root: Path
    _manifest_file: Path

    _is_transaction_active: bool

    def __init__(self, asset_manager: "AssetManager", name: str):
        """
        :meta private:
        """
        self._asset_manager = asset_manager
        self._name = name
        self._files = set()
        self._is_transaction_active = False
        self._root = self._asset_manager.root / name
        self._root.mkdir(parents=True, exist_ok=True)
        self._files_root = self._root / "files"
        self._files_root.mkdir(exist_ok=True)
        self._manifest_file = self._root / "manifest.json"

        try:
            with self._manifest_file.open("r") as fd:
                manifest = json.load(fd)
            self._files = set(manifest["files"])
            for fn in list(self._files):
                f = self._get(fn)
                if f.is_symlink() and not f.exists():
                    # Broken symlink; remove it
                    self._files.remove(fn)
                    f.unlink()
            self.sync()
        except FileNotFoundError:
            pass

    def _assert_valid_name(self, name: str) -> None:
        if not _is_valid_name(name):
            raise ValueError(f"Invalid asset name '{name}'")

    def transaction(self) -> AssetManagerTransaction:
        """
        Create a :class:`AssetManagerTransaction`.

        Only one transaction can be created at a time.

        :returns: The transaction
        :raises RuntimeError: when attempting to create a transaction while one already
            exists
        """
        # TODO: better locking mechanism?
        if self._is_transaction_active:
            raise RuntimeError(
                "Attempted to create transaction while one is already in progress"
            )
        self._is_transaction_active = True
        return AssetManagerTransaction(self)

    def sync(self, *, check: bool = True):
        """
        Syncs the manifest for this context to disk

        :param bool check: If true (default), check to make sure all files in the
            manifest exist, and that there are no extra files
        """
        if check:
            disk = set(self._files_root.iterdir())
            files = {self._files_root / f for f in self._files}
            for extra in disk - files:
                warn(
                    RuntimeWarning(
                        f"Unexpected item found in cache: '{str(extra)}'; removing..."
                    )
                )
                if extra.is_dir():
                    shutil.rmtree(extra)
                else:
                    extra.unlink()
            for missing in files - disk:
                raise RuntimeError(f"Cache item missing: '{str(missing)}'")
        with self._manifest_file.open("w") as fd:
            json.dump({"files": sorted(self._files)}, fd)

    def _add(self, name: str, *, force: bool = False) -> None:
        """
        Add an asset to the manifest

        :meta private:
        :param str name: The name of the asset
        :param bool force: If true, do not error if the asset already exists
        """
        self._assert_valid_name(name)
        if not force and name in self._files:
            raise FileExistsError(f"Asset already exists: '{name}'")
        self._files.add(name)

    def _rm(self, name: str, *, force: bool = False) -> None:
        """
        Remove an asset from the manifest

        :meta private:
        :param str name: The name of the asset
        :param bool force: If true, do not error if the asset does not exist
        """
        self._assert_valid_name(name)
        try:
            self._files.remove(name)
        except KeyError:
            if not force:
                raise FileNotFoundError(f"Asset not found: '{name}'")

    def ls(self) -> Iterable[str]:
        """
        List all files within this context

        :returns: The list of asset names
        """
        return self._files

    def _get(self, name: str) -> Path:
        """
        Retrieves the path for an asset with the given name, even if it does not already
        exist

        :meta private:
        """
        self._assert_valid_name(name)
        return self._files_root / name

    def exists(self, name: str) -> bool:
        """
        Queries if an asset exists

        :param str name: The name of the asset
        :returns: Whether or not it exists
        """
        self._assert_valid_name(name)
        return name in self._files

    def get(self, name: str) -> Path:
        """
        Retrieves the asset

        :param str name: The name of the asset
        :returns: The asset
        """
        if not self.exists(name):
            raise FileNotFoundError(f"Asset not found: '{name}'")
        return self._get(name)

    def get_mtime(self, name: str) -> float:
        """
        Retrieves the time an asset was modified

        :param str name: The name of the asset
        :returns: The time the asset was modified (:attr`os.stat_result.st_mtime`)
        """
        return self.get(name).stat().st_mtime

    def clear(self) -> None:
        """
        Clear all files in this context
        """
        for f in self.ls():
            self.get(f).unlink()
        self._files = set()
        self.sync(check=True)


class AssetManager:
    """
    Class for managing assets from challenges that are provided to competitors

    This class manages all assets under a given project.
    """

    project: "Project"
    root: Path

    def __init__(self, project: "rcds.Project"):
        self.project = project
        self.root = self.project.root / ".rcds-cache" / "assets"
        self.root.mkdir(parents=True, exist_ok=True)

    def create_context(self, name: str) -> AssetManagerContext:
        """
        Create a subcontext within the :class:`AssetManager`

        :param str name: The name of the context (challenge id)
        :raises ValueError: if the context name is not valid
        """
        if not _is_valid_name(name):
            raise ValueError(f"Invalid context name '{name}'")
        return AssetManagerContext(self, name)

    def list_context_names(self) -> Iterable[str]:
        """
        List the names of all subcontexts within this :class:`AssetManager`

        :returns: The contexts' names. Call :meth:`create_context` on a name to obtain a
            :class:`AssetManagerContext` object
        """
        for d in self.root.iterdir():
            if not d.is_dir():
                raise RuntimeError(f"Unexpected item found in cache: '{str(d)}'")
            yield d.name
