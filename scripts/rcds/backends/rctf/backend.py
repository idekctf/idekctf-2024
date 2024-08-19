import os
from hashlib import sha256
from pathlib import Path
from typing import Any, Dict, Set

import rcds
import rcds.backend
from rcds.util import deep_merge, load_any
from rcds.util.jsonschema import DefaultValidatingDraft7Validator

from .rctf import RCTFAdminV1

options_schema_validator = DefaultValidatingDraft7Validator(
    schema=load_any(Path(__file__).parent / "options.schema.yaml")
)


class ScoreboardBackend(rcds.backend.BackendScoreboard):
    _project: rcds.Project
    _options: Dict[str, Any]
    _adminv1: RCTFAdminV1

    def __init__(self, project: rcds.Project, options: Dict[str, Any]):
        self._project = project
        self._options = options

        for option_key in ["url", "token"]:
            env_key = f"RCDS_RCTF_{option_key.upper()}"
            self._options[option_key] = os.environ.get(
                env_key, self._options.get(option_key, None)
            )

        # FIXME: validate options better
        if not options_schema_validator.is_valid(self._options):
            raise ValueError("Invalid options")

        self._adminv1 = RCTFAdminV1(self._options["url"], self._options["token"])

    def patch_challenge_schema(self, schema: Dict[str, Any]) -> None:
        # Disallow regex flags
        flag_schema = next(
            s for s in schema["properties"]["flag"]["oneOf"] if s["type"] == "object"
        )
        flag_schema["properties"].pop("regex")
        flag_schema["oneOf"] = [
            s for s in flag_schema["oneOf"] if s["required"][0] != "regex"
        ]

        # tiebreakEligible flag
        schema["properties"]["tiebreakEligible"] = {
            "type": "boolean",
            "description": "Whether or not this challenge affects tiebreakers.",
            "default": True,
        }

        # sortWeight
        schema["properties"]["sortWeight"] = {
            "type": "number",
            "description": (
                "A parameter used for ordering when points and solves are equal."
            ),
            "default": 0,
        }

        schema["required"] += ["author", "category", "tiebreakEligible", "sortWeight"]

    def commit(self) -> bool:
        # Validate challenges
        for challenge in self._project.challenges.values():
            self.validate_challenge(challenge)

        for challenge in self._project.challenges.values():
            self.preprocess_challenge(challenge)

        # Begin actual commit
        remote_challenges: Set[str] = set(
            c["id"]
            for c in self._adminv1.list_challenges()
            if c.get("managedBy", None) == "rcds"
        )
        for challenge in self._project.challenges.values():
            if not challenge.config["visible"]:
                continue
            try:
                remote_challenges.remove(challenge.config["id"])
            except KeyError:
                pass
            self.commit_challenge(challenge)
        for chall_id in remote_challenges:
            print(f"Deleting {chall_id}")
            self._adminv1.delete_challenge(chall_id)
        return True

    def validate_challenge(self, challenge: rcds.Challenge) -> None:
        """
        Raises exception on validation fail
        """
        if isinstance(challenge.config["flag"], dict):
            if challenge.config["flag"]["regex"] is not None:
                raise ValueError("rCTF does not support regex flags")
            else:
                raise RuntimeError(
                    'Unexpected content in "flag" key on challenge config'
                )

    def preprocess_challenge(self, challenge: rcds.Challenge) -> None:
        chall_id = challenge.config["id"]
        if "sortOrder" in self._options:
            if chall_id in self._options["sortOrder"]:
                challenge.config["sortWeight"] = -self._options["sortOrder"].index(
                    chall_id
                )

    def commit_challenge(self, challenge: rcds.Challenge) -> None:
        chall_id = challenge.config["id"]
        rctf_challenge: Dict[str, Any] = {"managedBy": "rcds"}
        for common_field in [
            "name",
            "author",
            "category",
            "flag",
            "tiebreakEligible",
            "sortWeight",
        ]:
            rctf_challenge[common_field] = challenge.config[common_field]
        rctf_challenge["description"] = challenge.render_description()
        if "value" in challenge.config:
            # Static value
            rctf_challenge["points"] = {
                "min": challenge.config["value"],
                "max": challenge.config["value"],
            }
        else:
            # No value = dynamically scored
            rctf_challenge["points"] = {
                "min": self._options["scoring"]["minPoints"],
                "max": self._options["scoring"]["maxPoints"],
            }

        am_ctx = challenge.get_asset_manager_context()
        file_hashes: Dict[str, str] = dict()
        for filename in am_ctx.ls():
            h = sha256()
            with am_ctx.get(filename).open("rb") as fd:
                for chunk in iter(lambda: fd.read(5245288), b""):
                    h.update(chunk)
            file_hashes[filename] = h.hexdigest()
        file_urls: Dict[str, str] = {
            f: u
            for f, u in self._adminv1.get_url_for_files(file_hashes).items()
            if u is not None
        }
        deep_merge(
            file_urls,
            self._adminv1.create_upload(
                {
                    name: am_ctx.get(name).read_bytes()
                    for name in am_ctx.ls()
                    if name not in file_urls
                }
            ),
        )
        rctf_challenge["files"] = [
            {"name": name, "url": url} for name, url in file_urls.items()
        ]

        self._adminv1.put_challenge(chall_id, rctf_challenge)


class BackendsInfo(rcds.backend.BackendsInfo):
    HAS_SCOREBOARD = True

    def get_scoreboard(
        self, project: rcds.Project, options: Dict[str, Any]
    ) -> ScoreboardBackend:
        return ScoreboardBackend(project, options)


def get_info() -> BackendsInfo:
    return BackendsInfo()
