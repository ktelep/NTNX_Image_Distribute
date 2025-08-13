import urllib3
import requests
import pprint
import json
import time
import sys
import os
import re
import argparse
import configparser

from base64 import b64encode
from tqdm import tqdm
from tqdm.utils import CallbackIOWrapper
from datetime import datetime

"""
Suppress insecure connection warnings with urllib3
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
        payload = json.loads(snap_payload_template)

        payload['snapshot_specs'][0]['snapshot_name'] = snapshot_name
        payload['snapshot_specs'][0]['vm_uuid'] = vm_uuid

        res = self._post_request('snapshots',payload)
        return res

    def _post_request(self, url_target, pythonic_payload):
        url = self.url + url_target
        payload = json.dumps(pythonic_payload)
        try:
            response = requests.request('post', url, data=payload, headers=self.headers, verify=False)
        except requests.exceptions.RequestException as e:  
            raise SystemExit(e)
        res = response.json()
        return res
    
    def _get_request(self, url_target):
        url = self.url + url_target
        try:
            response = requests.request('get', url, headers=self.headers, verify=False)
        except requests.exceptions.RequestException as e:  
            raise SystemExit(e)   

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
        self.vtpm_config = None
        self.boot_config = None
        self.entity = None

    def load_entity(self, entity):
        self.name = entity['status']['name']
        self.description = None #TODO: Load description
        self.uuid = entity['metadata']['uuid']
        self.num_sockets = entity['status']['resources']['num_sockets']
        self.num_vcpus_per_socket = entity['status']['resources']['num_vcpus_per_socket']
        self.memory_size_mib = entity['status']['resources']['memory_size_mib']
        self.cluster_name = entity['status']['cluster_reference']['name']
        self.cluster_uuid = entity['status']['cluster_reference']['uuid']
        self.subnet = entity['status']['resources']['nic_list'][0]['subnet_reference']

        # Locate the correct disk, we want the SCSI disk at device index 0
        for disk in entity['status']['resources']['disk_list']:
            if disk['device_properties']['disk_address']['adapter_type'] == 'SCSI' and \
               disk['device_properties']['disk_address']['device_index'] == 0:
                   self.disk_uuid = entity['status']['resources']['disk_list'][0]['uuid']

        self.boot_config = entity['status']['resources']['boot_config']
        if 'vtpm_config' in entity['status']['resources']:
            self.vtpm_config = entity['status']['resources']['vtpm_config']
            # We have to remove the version field, as it's read-only
            if 'version' in self.vtpm_config:
                del self.vtpm_config['version']
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
        payload = {"kind":"subnet", "offset":0, "length":1000}  # Ask for 1000 subnets at a time
        subnet_resp = self._post_request("subnets/list",payload)

        for cluster in cl_resp['entities']:
            cluster_uuid = cluster['metadata']['uuid']
            cluster_name = cluster['spec']['name']
            if 'pc' not in cluster['status']['resources']['config']['build']['full_version']:
                self.clusters[cluster_uuid] = { "name":cluster_name,
                                                "spec":cluster['spec'],
                                                "cvm_ips":list(),
                                                "subnets":{}
                }
            
                for host in host_resp['entities']:
                    cluster_ref_uuid = host['status']['cluster_reference']['uuid']
                    cvm_ip = host['status']['resources']['controller_vm']['ip']
                    if cluster_ref_uuid == cluster_uuid:
                        self.clusters[cluster_uuid]['cvm_ips'].append(cvm_ip)

                for subnet in subnet_resp['entities']:
                    # Ignore overlays and non-VLAN networks
                    if subnet['spec']['resources']['subnet_type'] != 'VLAN':
                        continue

                    cluster_ref_uuid = subnet['spec']['cluster_reference']['uuid']
                    if cluster_ref_uuid == cluster_uuid:
                        self.clusters[cluster_uuid]['subnets'][subnet['status']['name']] = dict()
                        self.clusters[cluster_uuid]['subnets'][subnet['status']['name']]['uuid'] = subnet['metadata']['uuid']

            else:
                self.uuid = cluster_uuid
                self.name = cluster_name

    def _post_request(self, url_target, pythonic_payload):
        url = self.url + url_target
        payload = json.dumps(pythonic_payload)
        try:
            response = requests.request('post', url, data=payload, headers=self.headers, verify=False)
        except requests.exceptions.RequestException as e:  
            raise SystemExit(e)
        res = response.json()
        return res
    
    def _get_request(self, url_target):
        url = self.url + url_target
        try:
            response = requests.request('get', url, headers=self.headers, verify=False)
        except requests.exceptions.RequestException as e:  
            raise SystemExit(e)
        res = response.json()
        return res

    def _delete_request(self, url_target):
        url = self.url + url_target
        try:
            response = requests.request('delete', url, headers=self.headers, verify=False)
        except requests.exceptions.RequestException as e:  
            raise SystemExit(e)
        res = response.json()

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
                                                ],
                                    "boot_config": { "boot_device_order": ["DISK","NETWORK"],
                                                     "boot_type": "TBD"
                                                   }
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
        vm_spec['spec']['resources']['boot_config'] = vm.boot_config
        if vm.boot_config['boot_type'] == 'SECURE_BOOT':
            vm_spec['spec']['resources']['machine_type'] = "Q35"
        if vm.vtpm_config:
            vm_spec['spec']['resources']['vtpm_config'] = vm.vtpm_config

        res = self._post_request("vms",vm_spec) 
        return res['status']['execution_context']['task_uuid']

    def vm_by_name(self, vm_name):
        name_filter = f"vm_name=={vm_name}"
        payload = {"kind":"vm","filter":name_filter,"offset":0,"length":1000} 
        vm_resp = self._post_request("vms/list",payload)
        vm = VM()
        if 'entities' in vm_resp and len(vm_resp['entities']) > 0:
            vm.load_entity(vm_resp['entities'][0])
            return vm
        else:
            return None

    def vm_by_uuid(self, vm_uuid):
        vm_resp = self._get_request(f"vms/{vm_uuid}")
        vm = VM()
        vm.load_entity(vm_resp)
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
                for chunk in r.iter_content(chunk_size=8192):   # 8KB Chunks?
                    f.write(chunk)
                    pbar.update(len(chunk))
        return local_filename

    def remove_image(self, image_uuid):
        res = self._delete_request(f"images/{image_uuid}")
        return res 

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
    print (f" Waiting for task: {task_uuid} to complete")
    while True:
        res = pc.poll_for_task(task_uuid)
        perc = res['percentage_complete']
        if 'SUCCEEDED' in res['status']:
            print(f"   {perc}% Complete")
            return res
        elif 'FAILED' in res['status']:
            return None
        else:
            print(f"   {perc}% Complete")
            time.sleep(poll_time)

def snapshot_vm(vm_uuid, pc, pe_config):
    pass
    # Connect to PC and get VM's cluster UUID
    new_vm = pc.vm_by_uuid(vm_uuid)
    pe_ip = pc.clusters[new_vm.cluster_uuid]['cvm_ips'][0] 
    pe_name = pc.clusters[new_vm.cluster_uuid]['name']

    # Connect to PE and take snapshot
    pe = Prism_Element(pe_ip,pe_config[pe_name]['username'],pe_config[pe_name]['password'])
    snapshot_name = f"{new_vm.name} - Snapshot"
    res = pe.snap_vm(vm_uuid,snapshot_name)
    return (new_vm.name, snapshot_name, pe_name, res)

def pre_checks(source_pc, target_pc, vm_name, source_image_name, pe_config, all_targets):
    print()
    print("Running Pre-Checks")
    # Run some prechecks to make sure we're successful
    if source_pc.name == None or target_pc.name == None:
        print("Connection to one or both PC Instances is invalid")
        raise SystemExit()    
    print(" - Source and Target PC connections look good")

    if source_pc.uuid == target_pc.uuid:
        print("Source and Target Prism Centrals appear to be the same, check config file")
    print(" - Source and Target are different PCs")

    try:
        if not source_pc.vm_by_name(vm_name):
            print()
            print("Unable to collect information about Source VM from Prism Central")
            print(f" - Source VM named {vm_name} does not exist on Source PC")
            print("   Please verify the VM name, confirm capitalization and try again") 
            raise SystemExit() 
    except Exception as e:
        print("Unable to collect information about Source VM from Prism Central")
        raise SystemExit(e) 

    print()
    print(" - Source VM exists on the Source PC")

    if (re.search(r'[\[\]$,]', source_image_name)):
        print(f"Specified name for image includes invalid characters ( []?, )")
        raise SystemExit()

    print(" - Requested image name contains only valid characters")
    print()

    # Check that our target clusters exist on their respective PCs
    print(" - Checking target clusters exist and have valid networks")
    print()

    for cluster in all_targets:
        found = False
        for pc in [source_pc,target_pc]:
            for cl_uuid in pc.clusters.keys():
                if pc.clusters[cl_uuid]['name'] == cluster:
                    found = True
                    print(f"   Found target cluster {cluster} on PC {pc.name}")
                    break
        if not found:
            print(f"Unable to find target cluster {cluster} on either PC")
            raise SystemExit()

    print()
    print(" - All target clusters found on at least one PC")
    print()

    # Check that all our target clusters have a valid network
    for cluster in all_targets:
        found = False
        for pc in [source_pc,target_pc]:
            for cl_uuid in pc.clusters.keys():
                if pc.clusters[cl_uuid]['name'] == cluster:
                    if pe_config[cluster]['network_name'] in pc.clusters[cl_uuid]['subnets']:
                        found = True
                        print(f"   Found network {pe_config[cluster]['network_name']} on cluster {cluster}")
                        break
        if not found:
            print(f"Unable to find network {pe_config[cluster]['network_name']} on cluster {cluster}")
            raise SystemExit()
    print()
    print(" - All target clusters have a valid network")
    print()

    print(" - Everything Checks out, go for launch")
    print()


if __name__ == "__main__":

   # Parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("vm_name", help="Name of Virtual Machine on Source PC to distribute")
    parser.add_argument("-n", "--snapshot_name", help="Name for image and associated snapshots and VMs",
                        required=False)
    parser.add_argument("-c","--config", help="Name of Configuration File (default: config.ini)",
                        default="config.ini", required=False) 
    parser.add_argument("-k","--keep", help="Keep downloaded copy of disk image",
                        action="store_true", required=False)
    parser.add_argument("-d","--dryrun", help="Run all the prechecks but do not perform any actions",
                        action="store_true", required=False)
    args = parser.parse_args()

   # Identify our source VM
    source_vm_name = args.vm_name
   
   # Build our VM labels
    now = datetime.now()
    datecode = now.strftime("%Y%m%d%H%M")

    source_image_name = ""
    if not args.snapshot_name:
        source_image_name = f"{source_vm_name}_image_{datecode}"
    else:
        source_image_name = args.snapshot_name
    
    local_image_filename = f"{source_vm_name}_image_{datecode}.qcow2"

   # Read and parse config file 
    config = configparser.ConfigParser(interpolation=None)
    print(f"Parsing Config File: {args.config}")
    parsed = config.read(args.config)
    if not parsed:
        print("Unable to parse config file, please verify path and file contents")
        raise SystemExit()

    spc = config['source_pc']
    tpc = config['target_pc']

    # Identify all our target clusters
    source_cluster_targets = config['source_pc']['target_clusters'].split(",")
    target_cluster_targets = config['target_pc']['target_clusters'].split(",")
    all_targets = source_cluster_targets + target_cluster_targets

    pe_config = dict()

    # Check for and parse our credentials for PE
    # If they're defined in the cluster's stanza then they take precidence
    # Otherwise we look for global creds
    for pe_cluster in all_targets:
        pe_config[pe_cluster] = dict()
        if pe_cluster in config:
            if 'username' in config[pe_cluster] and 'password' in config[pe_cluster]:
                print(f" - Using specific credentials for cluster {pe_cluster}")
                pe_config[pe_cluster]['username'] = config[pe_cluster]['username']
                pe_config[pe_cluster]['password'] = config[pe_cluster]['password']
            elif 'pe_username' in config['global'] and 'pe_password' in config['global']:
                print(f" - Using global credentials for cluster {pe_cluster}")
                pe_config[pe_cluster]['username'] = config['global']['pe_username']
                pe_config[pe_cluster]['password'] = config['global']['pe_password']
            else:
                print(f"Unable to find PE credentials for cluster {pe_cluster} in config file")
                raise SystemExit()
        elif 'pe_username' in config['global'] and 'pe_password' in config['global']:
            print(f" - Using global credentials for cluster {pe_cluster}")
            pe_config[pe_cluster]['username'] = config['global']['pe_username']
            pe_config[pe_cluster]['password'] = config['global']['pe_password']
    
        else:
            print(f"Unable to find PE credentials for cluster {pe_cluster} in config file")
            raise SystemExit()  

        # Now check for network name
        if pe_cluster in config:
            if 'network_name' in config[pe_cluster]:
                print(f" - Using specific network for cluster {pe_cluster}")
                pe_config[pe_cluster]['network_name'] = config[pe_cluster]['network_name']
            elif config['global']['network_name']:
                print(f" - Using global network for cluster {pe_cluster}")
                pe_config[pe_cluster]['network_name'] = config['global']['network_name']
            else:
                print(f"Unable to find network name for cluster {pe_cluster} in config file")
                raise SystemExit()
        elif 'network_name' in config['global']:
            print(f" - Using global network for cluster {pe_cluster}")
            pe_config[pe_cluster]['network_name'] = config['global']['network_name']
        else:
            print(f"Unable to find network name for cluster {pe_cluster} in config file")
            raise SystemExit()

    # Check for and parse our networks for each cluster
    # Create our PC objects
    source_pc = Prism_Central(spc['ip'],spc['username'],spc['password'])
    target_pc = Prism_Central(tpc['ip'],tpc['username'],tpc['password'])

    # Connect to Source and Target Prism Centrals
    print()
    print("Creating connections to Prism Central Instances")
    print(" - Connecting to Source PC")
    source_pc.connect()
    print(" - Connecting to Target PC")
    target_pc.connect()

    # Run a few pre-checks to make sure our environment is sane
    pre_checks(source_pc, target_pc, source_vm_name, source_image_name, pe_config, all_targets)

    # Gather info on the source VM
    print()
    print(f"Gathering Information on source VM: {source_vm_name}")
    svm = source_pc.vm_by_name(source_vm_name)

    print(f" - VM uuid: {svm.uuid}")
    print(f" - Disk uuid: {svm.disk_uuid}")
    print(f" - Boot Type: {svm.boot_config['boot_type']}")
    if svm.vtpm_config:
        print("        vTPM: Enabled")

    if args.dryrun:
        print()
        print("Dry Run specified, exiting before making any changes")
        sys.exit(0)

    # TODO:  Use an in-band method to move the image if PEs are all attached to PCs in the same AZ

    # We don't have an AZ relationship between these PCs, so we'll use an out of band method
    # to move the image from Source PC to Target PC
    print() 
    print(f"Generating image from source VM")
    task_id = source_pc.generate_image(svm, source_image_name)
    completed_task = wait_for_task(source_pc, task_id)
    
   # Extract the source_image_uuid out of the completed task
   # Probably a better way to do this....
    source_image_uuid = completed_task['entity_reference_list'][0]['uuid']
    print(f" - Source Image name: {source_image_name} uuid: {source_image_uuid}")

   # Download the image locally
    print()
    print(f"Downloading Image to Local System - Filename: {local_image_filename}") 
    try:
        source_pc.download_image(source_image_uuid,local_image_filename)
    except Exception as e:
        print("An error occurred during download, cleaning up")
        source_pc.remove_image(source_image_uuid)
        os.unlink(local_image_filename)
        raise SystemExit(e)
         
   # Create our image at the target pc
    print()
    print("Creating Image object in Target Prism Central")
    task_id = target_pc.create_image(source_image_name)
    completed_task = wait_for_task(target_pc, task_id)
    target_image_uuid = completed_task['entity_reference_list'][0]['uuid']
    print(f" - Target Image name: {source_image_name} uuid: {target_image_uuid}")

   # Upload our image to the target pc
    print()
    print("Uploading Image to Target Prism Central")
    target_pc.upload_image(target_image_uuid,local_image_filename)

  # Create our new VMs
    output_info = list()
    print()
    for pc in [source_pc,target_pc]:
        output_info.append(f"Prism Central: {pc.name}")
        print(f"Creating VMs on clusters attached to {pc.name}")
        new_vm = VM()
        new_vm.description = "Generated VM from Distribution Script"
        new_vm.num_sockets = svm.num_sockets
        new_vm.num_vcpus_per_socket = svm.num_vcpus_per_socket
        new_vm.memory_size_mib = svm.memory_size_mib

       # We kick them off in parallel, then check them all at once for success
        source_tasks = list()
        for cluster_uuid in pc.clusters.keys():
            if (pc.clusters[cluster_uuid]['name'] in all_targets):
                cl_name = pc.clusters[cluster_uuid]['name']
                new_vm.subnet = pc.clusters[cluster_uuid]['subnets'][pe_config[cl_name]['network_name']]['uuid']
                new_vm.cluster_uuid = cluster_uuid

                # Transfer in our UEFI boot and vTPM config if applicable
                new_vm.boot_config = svm.boot_config
                if svm.vtpm_config:
                    new_vm.vtpm_config = svm.vtpm_config 

                if not args.snapshot_name:
                    new_vm.name = f"{source_vm_name}_VM_{pc.clusters[cluster_uuid]['name']}_{datecode}"
                else:
                    new_vm.name = f"{args.snapshot_name} VM"

                if pc.uuid == source_pc.uuid:
                    new_vm.disk_uuid = source_image_uuid
                else:
                    new_vm.disk_uuid = target_image_uuid

                print(f" - Creating VM {new_vm.name} on cluster {pc.clusters[cluster_uuid]['name']}")
                task_id = pc.create_vm(new_vm,cluster_uuid)
                source_tasks.append(task_id)

        source_vms = list()
        print()
        print("Waiting for VM creations to finish")
        for task_uuid in source_tasks:
            resp = wait_for_task(pc,task_uuid) 
            source_vms.append(resp['entity_reference_list'][0]['uuid'])

        print()
        print("Creating Snapshots on VMs")
        for vm in source_vms:
            res = snapshot_vm(vm,pc,pe_config)
            output_info.append(f"  Cluster: {res[2]}")
            output_info.append(f"       VM: {res[0]}")
            output_info.append(f"       Snap: {res[1]}")

        print(" - Completed Snapshots")

    if not args.keep:
        print()
        print("Cleaning up local image")
        os.unlink(local_image_filename)

    print()
    print("Process Complete")
    print("--------------------------")
    print(f"Source VM: {source_vm_name}")
    print(f"Image Name: {source_image_name}")
    print()
    print(" Cluster Report ")
    print(" -------------------------------")
    for i in output_info:
        print(f"   {i}")
    print()