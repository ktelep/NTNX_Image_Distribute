import urllib3
import requests
import pprint
import json
import time
import os
from base64 import b64encode
from tqdm import tqdm
from tqdm.utils import CallbackIOWrapper
from collections import namedtuple

""" 
Parameters
"""
source_ip='192.168.2.50'
source_user='admin'
source_pass='W0nderFu!!'

target_ip='192.168.2.40'
target_user='admin'
target_pass='W0nderFu!!'

pe_user='admin'
pe_pass='W0nderFu!!'

"""
suppress insecure connection warnings with urllib3
"""
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Setup the pretty printer for debug purposes
pp = pprint.PrettyPrinter(indent=4)

# Class for handing API v2 connections to PE
class Prism_Element:
    def __init__(self, pe_ip, pe_username, pe_password):
        self.ip_addr = pe_ip

        self.url = f"https://{self.ip_addr}:9440/PrismGateway/services/rest/v2.0/"
        self.creds = b64encode( bytes(f"{pe_username}:{pe_password}",encoding="ascii")).decode("ascii")
        self.auth_header = f"Basic {self.creds}"
        self.headers = {'Accept':'application/json',
                        'Content-Type':'application/json',
                        'Authorization': self.auth_header,
                        'cache-control': 'no-cache'}

        self.uuid = None
        self.name = None

    def connect(self):
        res = self._get_request('cluster')
        self.uuid = res['cluster_uuid']
        self.name = res['cluster_name']

        return

    def snap_vm(self, vm_uuid, snapshot_name):
        snap_payload_template = ''' { "snapshot_specs" : [ {"snapshot_name": "TBD", "vm_uuid": "TBD" }]} '''
        snap_payload = json.loads(snap_payload_template)

        snap_payload['snapshot_specs'][0]['snapshot_name'] = snapshot_name
        snap_payload['snapshot_specs'][0]['vm_uuid'] = vm_uuid
        payload = json.dumps(snap_payload)
        res = self._post_request('snapshots',payload)
        return res

    def _post_request(self, url_target, pythonic_payload):
        url = self.url + url_target
        payload = json.dumps(pythonic_payload)
        response = requests.request('post', url, data=payload, headers=self.headers, verify=False)
        res = response.json()
        return res
    
    def _get_request(self, url_target):
        url = self.url + url_target
        response = requests.request('get', url, headers=self.headers, verify=False)
        res = response.json()
        return res

# VM Class for holding our VM info when necessary
class VM:
    def __init__(self):
        self.name = None
        self.description = None
        self.uuid = None
        self.num_sockets = None
        self.num_vcpus_per_socket = None
        self.memory_size_mib = None
        self.cluster_name = None
        self.cluster_uuid = None
        self.subnet = None
        self.disk_uuid = None
        self.entity = None

    def load_entity(self, entity):
        self.name = entity['status']['name']
        self.description = None
        self.uuid = entity['metadata']['uuid']
        self.num_sockets = entity['status']['resources']['num_sockets']
        self.num_vcpus_per_socket = entity['status']['resources']['num_vcpus_per_socket']
        self.memory_size_mib = entity['status']['resources']['memory_size_mib']
        self.cluster_name = entity['status']['cluster_reference']['name']
        self.cluster_uuid = entity['status']['cluster_reference']['uuid']
        self.subnet = entity['status']['resources']['nic_list'][0]['subnet_reference']
        self.disk_uuid = entity['status']['resources']['disk_list'][0]['uuid']
        self.entity = entity

    def __repr__(self):
        return f"VM Name: {self.name} UUID: {self.uuid}"

# Class for handing PC connections via v3 API
class Prism_Central:
    def __init__(self, pc_ip, pc_username, pc_password):
        self.ip_addr = pc_ip

        self.url = f"https://{self.ip_addr}:9440/api/nutanix/v3/"
        self.creds = b64encode( bytes(f"{pc_username}:{pc_password}",encoding="ascii")).decode("ascii")
        self.auth_header = f"Basic {self.creds}"
        self.headers = {'Accept':'application/json',
                        'Content-Type':'application/json',
                        'Authorization': self.auth_header,
                        'cache-control': 'no-cache'}

        self.uuid = None
        self.name = None

        self.clusters = dict()

    def __repr__(self):
        return pprint.pformat(self.clusters, indent=4)

    def connect(self):
        # Connect to PC and get a list of the clusters and CVMs associated with it
        payload = {"kind":"cluster"}
        cl_resp = self._post_request("clusters/list",payload)
        payload = {"kind":"host"}
        host_resp = self._post_request("hosts/list",payload)

        for cluster in cl_resp['entities']:
            cluster_uuid = cluster['metadata']['uuid']
            cluster_name = cluster['spec']['name']
            if 'pc' not in cluster['status']['resources']['config']['build']['version']:
                self.clusters[cluster_uuid] = { "name":cluster_name,
                                                "spec":cluster['spec'],
                                                "cvm_ips":list()
                }
            
                for host in host_resp['entities']:
                    cluster_ref_uuid = host['status']['cluster_reference']['uuid']
                    cvm_ip = host['status']['resources']['controller_vm']['ip']
                    if cluster_ref_uuid == cluster_uuid:
                        self.clusters[cluster_uuid]['cvm_ips'].append(cvm_ip)

            else:
                self.uuid = cluster_uuid
                self.name = cluster_name

    def _post_request(self, url_target, pythonic_payload):
        url = self.url + url_target
        payload = json.dumps(pythonic_payload)
        response = requests.request('post', url, data=payload, headers=self.headers, verify=False)
        res = response.json()
        return res
    
    def _get_request(self, url_target):
        url = self.url + url_target
        response = requests.request('get', url, headers=self.headers, verify=False)
        res = response.json()
        return res

    def create_vm(self, vm, cluster_uuid):
        vm_spec_template = '''
         { "metadata": { "kind": "vm" },
           "spec": { "description": "TBD",
                     "resources": { "num_vcpus_per_socket": 0, 
                                    "memory_size_mib": 0,
                                    "disk_list": [ { "device_properties": { "disk_address": { "device_index": 0, 
                                                                                              "adapter_type": "SCSI" },
                                                     "device_type": "DISK"},
                                                     "data_source_reference": { "kind":"image", "uuid":"TBD" }
                                                    }
                                                 ],
                                    "nic_list": [ {"nic_type": "NORMAL_NIC",
                                                   "subnet_reference": { "kind": "subnet",
                                                   "uuid": "TBD" }
                                                  }
                                                ]
                                   },
            "name": "TBD",
            "cluster_reference": {
                "kind": "cluster",
                "uuid": "TBD"
             }
          }
        }'''

        vm_spec = json.loads(vm_spec_template)
        vm_spec['spec']['name'] = vm.name
        vm_spec['spec']['description'] = vm.description
        vm_spec['spec']['resources']['num_sockets'] = vm.num_sockets
        vm_spec['spec']['resources']['num_vcpus_per_socket'] = vm.num_vcpus_per_socket
        vm_spec['spec']['resources']['memory_size_mib'] = vm.memory_size_mib
        vm_spec['spec']['cluster_reference']['uuid'] = vm.cluster_uuid
        vm_spec['spec']['resources']['disk_list'][0]['data_source_reference']['uuid'] = vm.disk_uuid
        vm_spec['spec']['resources']['nic_list'][0]['subnet_reference']['uuid'] = vm.subnet

        res = self._post_request("vms",vm_spec) 
        return res['status']['execution_context']['task_uuid']

    def vm_by_name(self, vm_name):
        name_filter = f"vm_name=={vm_name}"
        payload = {"kind":"vm","filter":name_filter} 
        vm_resp = self._post_request("vms/list",payload)
        vm = VM()
        vm.load_entity(vm_resp['entities'][0])
        return vm

    def vm_by_uuid(self, vm_uuid):
        name_filter = f"vm_uuid=={vm_uuid}"
        payload = {"kind":"vm","filter":name_filter} 
        vm_resp = self._post_request("vms/list",payload)
        vm = VM()
        vm.load_entity(vm_resp['entities'][0])
        return vm
    
    def subnet_by_name(self, sn_name, cluster_uuid):
        name_filter = f"name=={sn_name}"
        payload = {"kind":"subnet","filter":name_filter}
        sn_resp = self._post_request("subnets/list", payload)
        subnet_uuid = None
        for net in sn_resp['entities']:
            if cluster_uuid in net['spec']['cluster_reference']['uuid']:
                subnet_uuid = net['metadata']['uuid']

        return subnet_uuid 

    def download_image(self, image_uuid, image_filename):
        local_filename=image_filename

        # Grab the image size in bytes
        res = self._get_request(f"images/{image_uuid}")
        image_size = res['status']['resources']['size_bytes']

        # Download the file, using tqdm for progress bar
        # We're doing our own post request here so we can do this cleanly
        request_url = self.url + f"images/{image_uuid}/file"
        with requests.get(request_url, stream=True, headers=self.headers, verify=False) as r:
            r.raise_for_status()
            with open(local_filename, 'wb') as f:
                pbar = tqdm(total=image_size, unit="B", unit_scale=True, unit_divisor=1024)
                for chunk in r.iter_content(chunk_size=1048576):   # 1MB chunks
                    f.write(chunk)
                    pbar.update(len(chunk))
        return local_filename

    def upload_image(self, image_uuid, local_filename):
        # Upload the file, using tqdm for progress bar 
        # We're doing our own put request here so we can do this cleanly
        # and we have to modify the headers
        upload_header = dict(self.headers)
        upload_header['Content-Type'] = 'application/octet-stream'

        # build our URL
        request_url = self.url + f"images/{image_uuid}/file"

        # Get our absolute path and file size for progress
        file_path = os.path.abspath(local_filename)
        file_size = os.stat(file_path).st_size

        # Upload
        with open(file_path, 'rb') as f:
            with tqdm(total=file_size, unit="B", unit_scale=True, unit_divisor=1024) as t:
                wrapped_file = CallbackIOWrapper(t.update, f, "read")
                requests.put(request_url, headers=upload_header, data=wrapped_file,verify=False)

        return image_uuid

    def generate_image(self, vm, image_name):
        image_spec_template = '''
            { "metadata": {"kind": "image"},
              "spec" : { "name": "TBD", 
                         "resources": { "image_type": "DISK_IMAGE", 
                                        "data_source_reference": { "kind": "vm_disk",
                                                                   "uuid": "TBD" }, 
                                        "initial_placement_ref_list": [ { "kind": "cluster", 
                                                                          "uuid": "TBD" } ] 
                                        } 
                        }
            }
        '''

        image_spec = json.loads(image_spec_template)
        image_spec['spec']['name'] = image_name
        image_spec['spec']['resources']['data_source_reference']['uuid'] = vm.disk_uuid
        image_spec['spec']['resources']['initial_placement_ref_list'][0]['uuid'] = vm.cluster_uuid

        resp = self._post_request("images",image_spec)
        return resp['status']['execution_context']['task_uuid']
        
    def create_image(self, image_name):
        image_create_template = '''
               { "metadata": { "kind": "image" },
                 "spec": { "name": "TBD", 
                          "resources": { "image_type": "DISK_IMAGE" } 
                        }
                }
        '''

        image_create = json.loads(image_create_template) 
        image_create['spec']['name'] = image_name
        resp = self._post_request("images",image_create)
        return resp['status']['execution_context']['task_uuid']


    def poll_for_task(self, task_uuid):
        response = self._get_request(f"tasks/{task_uuid}")
        return response

def wait_for_task(pc, task_uuid, poll_time=10):
    print (f"Waiting for task: {task_uuid} to complete")
    while True:
        res = pc.poll_for_task(task_uuid)
        perc = res['percentage_complete']
        if 'SUCCEEDED' in res['status']:
            print(f" - {perc}% Complete")
            return res
        elif 'FAILED' in res['status']:
            return None
        else:
            print(f" - {perc}% Complete")
            time.sleep(poll_time)

def snapshot_vm(vm_uuid, pc):
    pass
    # Connect to PC and get VM's cluster UUID
    new_vm = pc.vm_by_uuid(vm_uuid)
    pe_ip = pc['clusters'][new_vm['cluster_uuid']]['cvm_ips'][0] 
    # Connect to PE and take snapshot
    pe = Prism_Element(pe_ip,pe_user,pe_pass)
    res = pe.snap_vm(vm_uuid,f"{new_vm['name']}_SNAP")
    return res


if __name__ == "__main__":
    source_pc = Prism_Central(source_ip,source_user,source_pass)
    target_pc = Prism_Central(target_ip,target_user,target_pass)

   # Connect to Source and Target Prism Centrals
    source_pc.connect()
    target_pc.connect()

   # Identify our source VM
    source_vm_name = "GoldTest1"
    source_image_name = f"{source_vm_name}_image"
    local_image_filename = f"{source_vm_name}_image.qcow2"
    target_subnet_name = "Prod"

   # Gather info on the source VM
    print(f"Gathering Information on source VM: {source_vm_name}")
    svm = source_pc.vm_by_name(source_vm_name)

    print(f"- VM uuid: {svm.uuid}")
    print(f"- Disk uuid: {svm.disk_uuid}")

   
    print(f"Generating image from source VM")
    task_id = source_pc.generate_image(svm, source_image_name)
    completed_task = wait_for_task(source_pc, task_id)
    
   # Extract the source_image_uuid out of the completed task
   # Probably a better way to do this....
    source_image_uuid = completed_task['entity_reference_list'][0]['uuid']
    print(f"- Source Image uuid: {source_image_uuid}")

   # Download the image locally
    print("Downloading Image to Local System") 
    source_pc.download_image(source_image_uuid,local_image_filename)

   # Create our image at the target pc
    print("Creating Image object in Target Prism Central")
    task_id = target_pc.create_image(source_image_name)
    completed_task = wait_for_task(target_pc, task_id)
    target_image_uuid = completed_task['entity_reference_list'][0]['uuid']
    print(f"- Target Image uuid: {target_image_uuid}")

   # Upload our image to the target pc
    print("Uploading Image to Target Prism Central")
    target_pc.upload_image(target_image_uuid,local_image_filename)

   # Create our new VMs
    print("Creating VMs on all clusters attached to Source Prism Central")
    new_vm = VM()
    new_vm.description = "Generated VM from Distribution Script"
    new_vm.num_sockets = svm.num_sockets
    new_vm.num_vcpus_per_socket = svm.num_vcpus_per_socket
    new_vm.memory_size_mib = svm.memory_size_mib

   # Create VMs on clusters attached to the source
   # We kick them off in parallel, then check them all at once for success
    source_tasks = list()
    for cluster_uuid in source_pc.clusters.keys():
       # We need to determine the subnets attached and connect to that subnet                 
       print(f" - Determining network info for cluster {source_pc.clusters[cluster_uuid]['name']}")
       subnet_uuid = source_pc.subnet_by_name(target_subnet_name,cluster_uuid)
       new_vm.subnet = subnet_uuid
       new_vm.cluster_uuid = cluster_uuid
       new_vm.disk_uuid = source_image_uuid
       new_vm.name = f"{source_vm_name}_VM_{source_pc.clusters[cluster_uuid]['name']}"

       print(f" - Creating VM {new_vm.name}")
       task_id = source_pc.create_vm(new_vm,cluster_uuid)
       source_tasks.append(task_id)

    source_vms = list()
    for task_uuid in source_tasks:
       print(" - Waiting for VM creations to finish")
       resp = wait_for_task(source_pc,task_uuid) 
       source_vms.append(resp['entity_reference_list'][0]['uuid'])

    print(" - Creating Snapshots on VMs")
    for vm in source_vms:
        snapshot_vm(vm,source_pc)

   # Create VMs on clusters attached to the target
   # We kick them off in parallel, then check them all at once for success
    target_tasks = list()
    for cluster_uuid in target_pc.clusters.keys():
       # We need to determine the subnets attached and connect to that subnet                 
       print(f" - Determining network info for cluster {target_pc.clusters[cluster_uuid]['name']}")
       subnet_uuid = target_pc.subnet_by_name(target_subnet_name,cluster_uuid)
       new_vm.subnet = subnet_uuid
       new_vm.cluster_uuid = cluster_uuid
       new_vm.disk_uuid = source_image_uuid
       new_vm.name = f"{source_vm_name}_VM_{target_pc.clusters[cluster_uuid]['name']}"

       print(f" - Creating VM {new_vm.name}")
       task_id = target_pc.create_vm(new_vm,cluster_uuid)
       target_tasks.append(task_id)

    target_vms = list()
    for task_uuid in target_tasks:
       print(" - Waiting for VM creations to finish")
       resp = wait_for_task(target_pc,task_uuid) 
       target_vms.append(resp['entity_reference_list'][0]['uuid'])

    print(" - Creating Snapshots on VMs")
    for vm in target_vms:
        snapshot_vm(vm,target_pc)
    
    print("Complete")