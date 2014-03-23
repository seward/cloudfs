cloudfs
====
Cloudfs creates a virtual filesystem or block device on top of
popular cloud storage services.  This filesystem can only be
accessed with cloudfs.  It also supports transparent encryption
and zlib compression. As of right now, I only have support
for Amazon S3, but plan on adding others in the future.


Author
----
Benjamin Kittridge

bysin@bysin.net

http://byteworm.com


Requirements
----
1. Linux

2. libfuse



Compiling and installing
----
1. Run ./config.sh

2. Run make

3. Run make install or copy bin/cloudfs to /usr/sbin/

4. Copy bin/cloudfs.conf to ~/.cloudfs.conf

5. Edit ~/.cloudfs.conf


Command-line options for virtual filesystem
----
    Listing volumes:
        cloudfs --list
    
    Create a new volume:
        cloudfs --volume [volume] --create
    
    Mounting the volume:
        cloudfs --volume [volume] --mount [directory]
    
    Unmounting the volume:
        cloudfs --volume [volume] --unmount [directory]
    
    Deleting the volume:
        cloudfs --volume [volume] --delete


Command-line options for block device
----
    Listing volumes:
        cloudfs --list
    
    Create a new volume:
        cloudfs --volume [volume] --format block --size [size i.e. 30G] --create
    
    Mounting the volume:
        cloudfs --volume [volume] --mount /dev/nbd0
        
    Creating a ext3 filesystem:
        mkfs.ext3 /dev/nbd0
    
    Unmounting the volume:
        cloudfs --volume [volume] --unmount /dev/nbd0
    
    Deleting the volume:
        cloudfs --volume [volume] --delete


Tips and tricks
----
If you're going to use rsync with cloudfs, you'll see an improvement in
performance if you specify the " --inplace " flag with rsync. This
flag is not required, but highly recommended.

For automated scripts, you can add the " --force " flag to prevent
prompting.

You can't mount the same bucket twice at the same time for writing,
but you can use the " --readonly " flag to mount a bucket in read-only
mode.


