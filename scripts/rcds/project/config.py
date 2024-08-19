"""
Functions for loading project config files
"""

from itertools import tee
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple, Union, cast

import jsonschema  # type: ignore

from rcds import errors

from ..util import load_any
from ..util.jsonschema import DefaultValidatingDraft7Validator

config_schema_validator = DefaultValidatingDraft7Validator(
    schema=load_any(Path(__file__).parent / "rcds.schema.yaml"),
    format_checker=jsonschema.draft7_format_checker,
)


def parse_config(
    config_file: Path,
) -> Iterable[Union[errors.ValidationError, Dict[str, Any]]]:
    """
    Load and validate a config file, returning both the config and any
    errors encountered.

    :param pathlib.Path config_file: The challenge config to load
    :returns: Iterable containing any errors (all instances of
        :class:`rcds.errors.ValidationError`) and the parsed config. The config will
        always be last.
    """
    # root = config_file.parent
    config = load_any(config_file)
    schema_errors: Iterable[errors.SchemaValidationError] = (
        errors.SchemaValidationError(str(e), e)
        for e in config_schema_validator.iter_errors(config)
    )
    # Make a duplicate to check whethere there are errors returned
    schema_errors, schema_errors_dup = tee(schema_errors)
    # This is the same test as used in Validator.is_valid
    if next(schema_errors_dup, None) is not None:
        yield from schema_errors
    yield config


def check_config(
    config_file: Path,
) -> Tuple[Optional[Dict[str, Any]], Optional[Iterable[errors.ValidationError]]]:
    """
    Load and validate a config file, returning any errors encountered.

    If the config file is valid, the tuple returned contains the loaded config as
    the first element, and the second element is None. Otherwise, the second
    element is an iterable of errors that occurred during validation

    This method wraps :func:`parse_config`.

    :param pathlib.Path config_file: The challenge config to load
    """
    load_data = parse_config(config_file)
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


def load_config(config_file: Path) -> Dict[str, Any]:
    """
    Loads a config file, or throw an exception if it is not valid

    This method wraps :func:`check_config`, and throws the first error returned
    if there are any errors.

    :param pathlib.Path config_file: The challenge config to load
    :returns: The loaded config
    """
    config, errors = check_config(config_file)
    if errors is not None:
        raise next(iter(errors))
    # errors is None
    assert config is not None
    return config
