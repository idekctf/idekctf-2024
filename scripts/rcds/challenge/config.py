import re
from copy import deepcopy
from itertools import tee
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Any,
    Dict,
    Iterable,
    Optional,
    Pattern,
    Tuple,
    Union,
    cast,
)
from warnings import warn

import jsonschema  # type: ignore

from rcds import errors

from ..util import deep_merge, load_any
from ..util.jsonschema import DefaultValidatingDraft7Validator

if TYPE_CHECKING:
    from rcds import Project


config_schema = load_any(Path(__file__).parent / "challenge.schema.yaml")


class TargetNotFoundError(errors.ValidationError):
    pass


class TargetFileNotFoundError(TargetNotFoundError):
    target: Path

    def __init__(self, message: str, target: Path):
        super().__init__(message)
        self.target = target


class InvalidFlagError(errors.ValidationError):
    pass


class ConfigLoader:
    """
    Object that manages loading challenge config files
    """

    project: "Project"
    config_schema: Dict[str, Any]
    config_schema_validator: Any
    _flag_regex: Optional[Pattern[str]] = None

    def __init__(self, project: "Project"):
        """
        :param rcds.Project project: project context to use
        """
        self.project = project
        self.config_schema = deepcopy(config_schema)

        # Load flag regex if present
        if "flagFormat" in self.project.config:
            self._flag_regex = re.compile(f"^{self.project.config['flagFormat']}$")

        # Backend config patching
        for backend in [
            self.project.container_backend,
            self.project.scoreboard_backend,
        ]:
            if backend is not None:
                backend.patch_challenge_schema(self.config_schema)
        self.config_schema_validator = DefaultValidatingDraft7Validator(
            schema=self.config_schema, format_checker=jsonschema.draft7_format_checker
        )

    def _apply_defaults(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply project-level defaults
        """
        try:
            root_defaults = deepcopy(self.project.config["defaults"])
        except KeyError:
            # No defaults present
            return config

        container_defaults = root_defaults.pop("containers", None)
        expose_defaults = root_defaults.pop("expose", None)

        # Array types with no sensible defaults - ignore them
        root_defaults.pop("provide", None)

        config = deep_merge(root_defaults, config)
        if container_defaults is not None and "containers" in config:
            for container_name, container_config in config["containers"].items():
                config["containers"][container_name] = deep_merge(
                    dict(), container_defaults, container_config
                )
        if expose_defaults is not None and "expose" in config:
            for expose_config in config["expose"].values():
                for i, expose_port in enumerate(expose_config):
                    expose_config[i] = deep_merge(dict(), expose_defaults, expose_port)
        return config

    def parse_config(
        self, config_file: Path
    ) -> Iterable[Union[errors.ValidationError, Dict[str, Any]]]:
        """
        Load and validate a config file, returning both the config and any
        errors encountered.

        :param pathlib.Path config_file: The challenge config to load
        :returns: Iterable containing any errors (all instances of
            :class:`rcds.errors.ValidationError`) and the parsed config. The config will
            always be last.
        """
        root = config_file.parent
        relative_path = root.resolve().relative_to(self.project.root.resolve())
        config = load_any(config_file)

        config.setdefault("id", root.name)  # derive id from parent directory name

        config = self._apply_defaults(config)

        if len(relative_path.parts) >= 2:
            # default category name is the parent of the challenge directory
            config.setdefault("category", relative_path.parts[-2])

        schema_errors: Iterable[errors.SchemaValidationError] = (
            errors.SchemaValidationError(str(e), e)
            for e in self.config_schema_validator.iter_errors(config)
        )
        # Make a duplicate to check whethere there are errors returned
        schema_errors, schema_errors_dup = tee(schema_errors)
        # This is the same test as used in Validator.is_valid
        if next(schema_errors_dup, None) is not None:
            yield from schema_errors
        else:
            if "expose" in config:
                if "containers" not in config:
                    yield TargetNotFoundError(
                        "Cannot expose ports without containers defined"
                    )
                else:
                    for key, expose_objs in config["expose"].items():
                        if key not in config["containers"]:
                            yield TargetNotFoundError(
                                f'`expose` references container "{key}" but '
                                f"it is not defined in `containers`"
                            )
                        else:
                            for expose_obj in expose_objs:
                                if (
                                    expose_obj["target"]
                                    not in config["containers"][key]["ports"]
                                ):
                                    yield TargetNotFoundError(
                                        f"`expose` references port "
                                        f'{expose_obj["target"]} on container '
                                        f'"{key}" which is not defined'
                                    )
            if "provide" in config:
                for f in config["provide"]:
                    if isinstance(f, str):
                        f = Path(f)
                    else:
                        f = Path(f["file"])
                    if not (root / f).is_file():
                        yield TargetFileNotFoundError(
                            f'`provide` references file "{str(f)}" which does not '
                            f"exist",
                            f,
                        )
            if "flag" in config:
                if isinstance(config["flag"], dict):
                    if "file" in config["flag"]:
                        f = Path(config["flag"]["file"])
                        f_resolved = root / f
                        if f_resolved.is_file():
                            with f_resolved.open("r") as fd:
                                flag = fd.read().strip()
                            config["flag"] = flag
                        else:
                            yield TargetFileNotFoundError(
                                f'`flag.file` references file "{str(f)}" which does '
                                f"not exist",
                                f,
                            )
                if isinstance(config["flag"], str):
                    if self._flag_regex is not None and not self._flag_regex.match(
                        config["flag"]
                    ):
                        yield InvalidFlagError(
                            f'Flag "{config["flag"]}" does not match the flag format'
                        )
                    if config["flag"].count("\n") > 0:
                        warn(
                            RuntimeWarning(
                                "Flag contains multiple lines; is this intended?"
                            )
                        )
        yield config

    def check_config(
        self, config_file: Path
    ) -> Tuple[Optional[Dict[str, Any]], Optional[Iterable[errors.ValidationError]]]:
        """
        Load and validate a config file, returning any errors encountered.

        If the config file is valid, the tuple returned contains the loaded config as
        the first element, and the second element is None. Otherwise, the second
        element is an iterable of errors that occurred during validation

        This method wraps :meth:`parse_config`.

        :param pathlib.Path config_file: The challenge config to load
        """
        load_data = self.parse_config(config_file)
        load_data, load_data_dup = tee(load_data)
        first = next(load_data_dup)
        if isinstance(first, errors.ValidationError):
            validation_errors = cast(
                Iterable[errors.ValidationError],
                filter(lambda v: isinstance(v, errors.ValidationError), load_data),
            )
            return (None, validation_errors)
        else:
            return (first, None)

    def load_config(self, config_file: Path) -> Dict[str, Any]:
        """
        Loads a config file, or throw an exception if it is not valid

        This method wraps :meth:`check_config`, and throws the first error returned
        if there are any errors.

        :param pathlib.Path config_file: The challenge config to load
        :returns: The loaded config
        """
        config, errors = self.check_config(config_file)
        if errors is not None:
            raise next(iter(errors))
        # errors is None
        assert config is not None
        return config
