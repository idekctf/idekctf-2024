"""
Error types for various rCDS methods
"""

import jsonschema.exceptions  # type: ignore


class ValidationError(ValueError):
    pass


class SchemaValidationError(ValidationError):
    cause: jsonschema.exceptions.ValidationError

    def __init__(self, message: str, cause: jsonschema.exceptions.ValidationError):
        super().__init__(message)

        self.cause = cause
