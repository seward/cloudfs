#!/usr/bin/python
#
# cloudfs: Script for backing up files at regular intervals to cloudfs
#	By Benjamin Kittridge. Copyright (C) 2014, All rights reserved.
#

import datetime
import os
import string
import subprocess
import time
import types
import fcntl

########################################################################
# Configuration - PLEASE EDIT

# Path to write the log file. This file will contain log information
# about what files are being backed up.
LOG_FILE = "/path/to/backup.log"

# Path to the cloudfs binary.
CLOUDFS_PATH = "/usr/sbin/cloudfs"

# Path to the cloudfs config file.
CONFIG_FILE = "/path/to/.cloudfs.conf"

# Path to the directory used for mounted cloudfs backups.
# This is not the directory you are backing up, but rather the
# directory to mount the backup to. e.g. /mnt/backup
BACKUP_DIR = "/path/to/temp/directory"

# Hours to wait between backups.
HOUR_WAIT = 48

# Array of dicts containing information about backups. Each dict
# should have atleast a 'volume' and 'path' key.
BACKUPS = [
	{
		'volume': 'example1',
		'path': '/home/foobar',
		'exclude': ['.thumbnails', '.cache'],
	}, {
		'volume': 'example2',
		'path': 'root@remote:/',
		'one_file_system': True,
	}
]

########################################################################
# Backup script

DEBUG = False

assert HOUR_WAIT > 0, "HOUR_WAIT should be set to a number greater than 0"

if os.fork() != 0:
	os._exit(0)

def uexec(args):
	if DEBUG:
		if type(args) is types.StringType:
			log("=== %s" % args)
		else:
			log("=== %s" % string.join(args))
	return subprocess.Popen(args, stdout=subprocess.PIPE,
	                              stderr=subprocess.PIPE)

def unmount():
	fuser = uexec(["fusermount", "-u", BACKUP_DIR])
	fuser.communicate()

def ismounted():
	mount = uexec(["mount"])
	out, err = mount.communicate()
	line = "cloudfs on %s type fuse.cloudfs" % BACKUP_DIR
	if line in out.rstrip():
		return True
	return False

def log(str):
	if not hasattr(log, "file"):
		log.file = open(LOG_FILE, "a")
	for line in string.split(str, "\n"):
		ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
		log.file.write("%s | %s\n" % (ts, line))
		log.file.flush()

def pollout(pids, timeout=5):
	for pid in pids:
		fcntl.fcntl(pid.stdout.fileno(), fcntl.F_SETFL, os.O_NONBLOCK)
		fcntl.fcntl(pid.stderr.fileno(), fcntl.F_SETFL, os.O_NONBLOCK)
	for t in range(timeout):
		fds = []
		for pid in pids:
			pid.poll()
			fds.append(pid.stdout)
			fds.append(pid.stderr)
		for fd in fds:
			while True:
				try:
					output = fd.readline()
					if not output:
						break;
					log(output.rstrip())
				except IOError:
					break
		time.sleep(1)

def backup(volume, path, exclude=None, one_file_system=False, disabled=False):
	if disabled:
		return

	log("Backing up \"%s\" ..." % volume)

	# Attempt to create backup directory if it doesn't exist.
	try:
		os.makedirs(BACKUP_DIR);
	except os.error:
		pass

	# Make sure backup directory is unmounted before mounting.
	unmount()
	while ismounted():
		log("Waiting for %s to unmount" % BACKUP_DIR)
		time.sleep(5)

	# Call cloudfs to mount volume.
	cloudfs = uexec([CLOUDFS_PATH, "--config", CONFIG_FILE, "--force",
			"--nofork", "--volume", volume, "--mount", BACKUP_DIR])

	# Wait until backup directory is mounted.
	while not ismounted():
		pollout([cloudfs])
		if cloudfs.returncode is not None:
			log("Error mounting volume, cloudfs unexpectedly terminated")
			return
		log("Waiting for %s to mount" % BACKUP_DIR)

	# Call rsync on source to backup directory.
        options = []
        if one_file_system:
                options.append("--one-file-system")
        if exclude:
                if type(exclude) is types.StringType:
                        options.append("--exclude")
                        options.append(exclude)
                elif type(exclude) is types.ListType:
                        for e in exclude:
                                options.append("--exclude")
                                options.append(e)
                else:
                        log("Invalid type for exclude")
                        unmount()
                        return;

        paths = []
        if type(path) is types.StringType:
                paths.append(path)
        elif type(path) is types.ListType:
                paths += path
        else:
                log("Invalid type for path")
                unmount()
                return;

        rsync = uexec(["rsync", "--delete", "--inplace", "--whole-file",
                        "-avp"] + options + paths + [BACKUP_DIR])
	while rsync.returncode is None:
		pollout([cloudfs, rsync])
		if cloudfs.returncode is not None:
			rsync.kill()
			log("Error, cloudfs unexpectedly terminated")
			return

	# Unmount backup directory and wait for cloudfs to terminate.
	unmount()
	cloudfs.wait()

while True:
	log("Backup started")
	for entry in BACKUPS:
		backup(**entry)
	log("Backup finished")
	time.sleep(60 * 60 * HOUR_WAIT)

