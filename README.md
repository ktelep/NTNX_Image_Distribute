# image_distribute.py

Python script for distribution of VM images for Citrix across multiple PCs and Clusters

## Install the required modules (tqdm, urllib3, and requests)

    pip install -r requirements.txt

## Modify the config.ini file appropriately

**[global]** section is for providing global settings for prism element username, password, and the Subnet Name that the VMs will be attached to.  This can be overridden for specific clusters later if necessary.

- pe_username = Prism Element Username
- pe_password = Prism Element Password
- network_name = Name of the subnet

**[source_pc]** and **[target_pc]** sections provide the IP and credentials for your source and target prism central instances, along with a comma separated list of the clusters you'd like the image to be created on.   Be sure to include the source cluster in this list also for consistency across your environment

**[ClusterName]** stanzas provide the ability to override the global settings on a cluster by cluster basis.   If you do not include this stanza, then the defaults will be used.   You can override credentials, network name, or both.

- username = Prism Element Username
- password = Prism Element Password
- network_name = Name of Subnet to use

## Run the Script

    python3 image_distribute.py <GoldImageVMName>

You can optionally pass the following parameters:

-n :  Name you would like the image and resulting VMs to have on each cluster, wrap in quotes if this contains spaces

-c :  Specify a non-default config file and location (default is config.ini in the current directory)

-k :  Keep the local copy of the image and do not delete it after uploading to target

-d :  Dry run, perform all checks but do not actually execute the distribution process

As an example, naming the image 'Citrix Desktop - MyUpdated - Patched 10-14-2023' using VM named "VQ2UA202" as the source VM (Note the quotes around the name)

    python3 image_distribute.py -n "Citrix Desktop - MyUpdated - Patched 10-14-2023" VQ2UA202

## What does it do?

1. Confirms all PCs are accessible, Networks all exist on all clusters, and source VM exists
2. Creates an image from the identified "Gold" VM
3. Downloads the image to the local system
4. Uploads the image to the target PC
5. Creates VMs on every cluster attached to both source and target PCs based off of the image
6. Creates a snapshot of each VM at the PE level in preparation for Citrix use

