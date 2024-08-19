from copy import deepcopy
from typing import List, Tuple, Union


def deep_merge(a: dict, *rest: dict) -> dict:
    """
    Deep merge remaining arguments from left to right into `a`. Mutates `a`,
    does not mutate any other arguments.

    :param a dict:
    :return: the merged dictionary
    :rtype: dict
    """
    _rest: Union[List[dict], Tuple[dict, ...]] = rest
    while len(_rest) > 0:
        b, *_rest = _rest
        for key in b:
            if isinstance(b[key], dict):
                if key in a and isinstance(a[key], dict):
                    deep_merge(a[key], b[key])
                else:
                    a[key] = deepcopy(b[key])
            else:
                a[key] = b[key]
    return a
