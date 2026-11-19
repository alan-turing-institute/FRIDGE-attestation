from kubernetes import config
from kubernetes.client import CoreV1Api

def k8s_client() -> CoreV1Api:
    config.load_kube_config()
    return CoreV1Api()
