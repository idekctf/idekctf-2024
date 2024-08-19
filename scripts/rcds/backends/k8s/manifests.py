import re
from typing import Any, Callable, Dict, Iterable, List, Set

from kubernetes import client  # type: ignore

AnyManifest = Dict[str, Any]


# namespaced manifests only - namespaces are handled separately
MANIFEST_KINDS = ["Deployment", "Service", "Ingress", "NetworkPolicy"]
KIND_TO_API_VERISON = {
    "Deployment": "apps/v1",
    "Service": "v1",
    "Ingress": "networking.k8s.io/v1",
    "NetworkPolicy": "networking.k8s.io/v1",
}


camel_case_to_snake_case_re = re.compile(r"(?=[A-Z])")


def kind_to_api_method_postfix(kind: str) -> str:
    return "_namespaced" + camel_case_to_snake_case_re.sub("_", kind).lower()


def get_api_method_for_kind(api_client: Any, method: str, kind: str) -> Callable:
    return getattr(api_client, method + kind_to_api_method_postfix(kind))


def labels_to_label_selector(labels: Dict[str, str]) -> str:
    selector = ""
    for k, v in labels.items():
        selector += f"{k}={v},"
    return selector[:-1]


def sync_manifests(all_manifests: Iterable[Dict[str, Any]]):
    v1 = client.CoreV1Api()
    appsv1 = client.AppsV1Api()
    networkingv1 = client.NetworkingV1Api()
    networkingv1beta1 = client.NetworkingV1beta1Api()

    api_version_to_client = {
        "v1": v1,
        "apps/v1": appsv1,
        "networking.k8s.io/v1": networkingv1,
        "networking.k8s.io/v1beta1": networkingv1beta1,
    }

    manifests_by_namespace_kind: Dict[str, Dict[str, List[Dict[str, Any]]]] = dict()
    namespaces: List[Dict[str, Any]] = []

    for manifest in all_manifests:
        kind = manifest["kind"]
        if kind == "Namespace":
            namespaces.append(manifest)
        else:
            namespace = manifest["metadata"]["namespace"]
            manifests_by_namespace_kind.setdefault(namespace, dict())
            manifests_by_namespace_kind[namespace].setdefault(kind, [])
            manifests_by_namespace_kind[namespace][kind].append(manifest)

    server_namespaces_names: Set[str] = set(
        map(
            lambda ns: ns.metadata.name,
            v1.list_namespace(label_selector="app.kubernetes.io/managed-by=rcds").items,
        )
    )

    for namespace_manifest in namespaces:
        namespace = namespace_manifest["metadata"]["name"]

        try:
            server_namespaces_names.remove(namespace)
            # the namespace already exists; patch it
            print(f"PATCH Namespace {namespace}")
            v1.patch_namespace(namespace, namespace_manifest)
        except KeyError:
            # the namespace doesn't exist; create it
            print(f"CREATE Namespace {namespace}")
            v1.create_namespace(namespace_manifest)

        # TODO: Potentially decouple this from the namespace's labels?
        # Common labels for rCDS manifests in this namespace
        ns_labels: Dict[str, str] = namespace_manifest["metadata"]["labels"]
        ns_labels.pop("name")

        # Process all manifest kinds we know about in this namespace
        for kind in MANIFEST_KINDS:
            manifests = manifests_by_namespace_kind[namespace].get(kind, [])
            server_manifest_names: Set[str] = set(
                map(
                    lambda m: m.metadata.name,
                    get_api_method_for_kind(
                        api_version_to_client[KIND_TO_API_VERISON[kind]], "list", kind
                    )(
                        namespace, label_selector=labels_to_label_selector(ns_labels)
                    ).items,
                )
            )
            for manifest in manifests:
                manifest_name = manifest["metadata"]["name"]
                try:
                    server_manifest_names.remove(manifest_name)
                    # the manifest already exists; patch it
                    print(f"PATCH {kind} {namespace}/{manifest_name}")
                    try:
                        get_api_method_for_kind(
                            api_version_to_client[manifest["apiVersion"]], "patch", kind
                        )(manifest_name, namespace, manifest)
                    except client.rest.ApiException:
                        # Conflict of some sort - let's just delete and recreate it
                        print(f"DELETE {kind} {namespace}/{manifest_name}")
                        get_api_method_for_kind(
                            api_version_to_client[manifest["apiVersion"]],
                            "delete",
                            kind,
                        )(manifest_name, namespace)
                        print(f"CREATE {kind} {namespace}/{manifest_name}")
                        get_api_method_for_kind(
                            api_version_to_client[manifest["apiVersion"]],
                            "create",
                            kind,
                        )(namespace, manifest)
                except KeyError:
                    # the manifest doesn't exist; create it
                    print(f"CREATE {kind} {namespace}/{manifest_name}")
                    get_api_method_for_kind(
                        api_version_to_client[manifest["apiVersion"]], "create", kind
                    )(namespace, manifest)
            for manifest_name in server_manifest_names:
                print(f"DELETE {kind} {namespace}/{manifest_name}")
                get_api_method_for_kind(
                    api_version_to_client[KIND_TO_API_VERISON[kind]], "delete", kind
                )(manifest_name, namespace)

    for namespace_name in server_namespaces_names:
        print(f"DELETE Namespace {namespace_name}")
        v1.delete_namespace(namespace_name)
