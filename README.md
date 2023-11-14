# image_distribute.py

Python script for distribution of VM images for Citrix across multiple PCs and Clusters

## Install the required modules (tqdm, urllib3, and requests)

    pip install -r requirements.txt

## Modify the config.ini file appropriately

**[global]** section provides the Name for the subnet as defined in PC that the Citrix VMs will be attached to

**[source_pc]** and **[target_pc]** sections provide the IP and credentials for your source and target prism central instances

**[prism_element]** provides the credentials for the PRism Element clusters.  You do not need to provide an IP address here, as they are discovered from the Prism Central Instances

## Run the Script

    python3 image_distribute.py <GoldImageVMName>

You can optionally pass the following parameters:

-n :  Name you would like the image and resulting VMs to have on each cluster, wrap in quotes if this contains spaces

-c :  Specify a non-default config file and location (default is config.ini in the current directory)

-k :  Keep the local copy of the image and do not delete it after uploading to target

As an example, naming the image 'Citrix Desktop - MyUpdated - Patched 10-14-2023' using VM named "VQ2UA202" as the source VM (Note the quotes around the name)

    python3 image_distribute.py -n "Citrix Desktop - MyUpdated - Patched 10-14-2023" VQ2UA202

## What does it do?

1. Confirms all PCs are accessible, Networks all exist on all clusters, and source VM exists
2. Creates an image from the idenfied "Gold" VM
3. Downloads the image to the local system
4. Uploads the image to the target PC
5. Creates VMs on every cluster attached to both source and target PCs based off of the image
6. Creates a snapshot of each VM at the PE level in preparation for Citrix use

## Assumptions

1. Network name is the same across all PE clusters
2. All PE clusters use the same user/pass
