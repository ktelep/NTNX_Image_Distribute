# image_distribute.py

Python script for distribution of VM images for Citrix across multiple PCs and Clusters

Install the required modules

    pip install -r requirements.txt

Modify the config.ini file appropriately

Run the Script

What does it do?

1. Creates an image from the idenfied "Gold" VM
2. Downloads the image to the local system
2. Uploads the image to the target PC
3. Creates VMs on every cluster attached to both source and target PCs based off of the image
4. Creates a snapshot of each VM at the PE level in preparation for Citrix use