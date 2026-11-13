from typing import Any

from kubernetes.client import CoreV1Api
from kubernetes.client.models import V1NodeList, V1Pod, V1PodList
from kubernetes.stream import stream

from .kubernetes import k8s_client

def fetch_report(api_instance, pod: str) -> str:
    exec_command = [
        '/bin/sh',
        '-c',
        'cat /result.jwt'
    ]
    response = stream(
        api_instance.connect_get_namespaced_pod_exec,
        pod.metadata.name,
        pod.metadata.namespace,
        command=exec_command,
        stdout=True,
        stdin=False,
        stderr=False,
        tty=False,
    )
    return response

def get_cvm_nodes(api_instance: CoreV1Api) -> V1NodeList:
    return api_instance.list_node(
        label_selector='kubernetes.azure.com/security-type=ConfidentialVM',
        watch=False
    )

def get_guest_attest_pods(api_instance: CoreV1Api) -> V1PodList:
    return api_instance.list_pod_for_all_namespaces(
        label_selector='name=guest-attest',
        watch=False
    )

def main() -> None:
    api_instance = k8s_client()
    cvm_nodes = get_cvm_nodes(api_instance)
    for node in cvm_nodes.items:
        print(node.metadata.name)
    guest_attest_pods = get_guest_attest_pods(api_instance)
    for pod in guest_attest_pods.items:
        print(pod.spec.node_name, pod.metadata.name, pod.metadata.namespace)

    report = fetch_report(api_instance, guest_attest_pods.items[0])
    print(report)

if __name__ == "__main__":
    main()
