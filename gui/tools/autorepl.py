#!/usr/bin/env python
#-
# Copyright (c) 2011 iXsystems, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#

import datetime
import logging
import os
import sys

sys.path.extend([
    '/usr/local/www',
    '/usr/local/www/freenasUI',
])

from django.core.management import setup_environ
from freenasUI import settings
setup_environ(settings)

from freenasUI.storage.models import Replication
from freenasUI.common.timesubr import isTimeBetween
from freenasUI.common.pipesubr import pipeopen, system
from freenasUI.common.locks import mntlock
from freenasUI.common.system import send_mail

# DESIGN NOTES
#
# A snapshot transists its state in its lifetime this way:
#   NEW                         A newly created local snapshot by autosnap for a filesystem which has replicated set-up
#   In_Progress                 A local snapshot which is in the process of being replicated
#   Latest                      A local snapshot marked to be the latest one and as such 'held' by the replication system
#   Replicated                  A local snapshot which has been replicated to a remote system
#   Latest_Replica              A remote snapshot marked to be the latest one and as such 'held' by the replication system
#   Replica                     A remote snapshot
#   -                           A snapshot which has no involvement in the replication process
#

log = logging.getLogger('tools.autorepl')

# Set to True if verbose log desired
debug = False

# Detect if another instance is running
def exit_if_running(pid):
    log.debug("Checking if process %d is still alive" % (pid, ))
    try:
        os.kill(pid, 0)
        # If we reached here, there is another process in progress
        log.debug("Process %d still working, quitting" % (pid, ))
        sys.exit(0)
    except OSError:
        log.debug("Process %d gone" % (pid, ))

MNTLOCK = mntlock()

mypid = os.getpid()

now = datetime.datetime.now().replace(microsecond=0)
if now.second < 30 or now.minute == 59:
    now = now.replace(second=0)
else:
    now = now.replace(minute=now.minute + 1, second=0)
now = datetime.time(now.hour, now.minute)

# (mis)use MNTLOCK as PIDFILE lock.
locked = True
try:
    MNTLOCK.lock_try()
except IOError:
    locked = False
if not locked:
    sys.exit(0)

AUTOREPL_PID = -1
try:
    with open('/var/run/autorepl.pid') as pidfile:
        AUTOREPL_PID = int(pidfile.read())
except:
    pass

if AUTOREPL_PID != -1:
    exit_if_running(AUTOREPL_PID)

with open('/var/run/autorepl.pid', 'w') as pidfile:
    pidfile.write('%d' % mypid)

MNTLOCK.unlock()

# At this point, we are sure that only one autorepl instance is running.

log.debug("Autosnap replication started")

# Traverse all replication tasks
replication_tasks = Replication.objects.all()
for replication in replication_tasks:
    if not isTimeBetween(now, replication.repl_begin, replication.repl_end):
        continue

    remote = replication.repl_remote.ssh_remote_hostname.__str__()
    remote_port = replication.repl_remote.ssh_remote_port
    dedicateduser = replication.repl_remote.ssh_remote_dedicateduser
    fast_cipher = replication.repl_remote.ssh_fast_cipher
    remotefs = replication.repl_zfs.__str__()
    localfs = replication.repl_filesystem.__str__()
    last_snapshot = ''
    resetonce = replication.repl_resetonce

    if fast_cipher:
        sshcmd = ('/usr/bin/ssh -c arcfour256,arcfour128,blowfish-cbc,'
                  'aes128-ctr,aes192-ctr,aes256-ctr -i /data/ssh/replication'
                  ' -o BatchMode=yes -o StrictHostKeyChecking=yes -q')
    else:
        sshcmd = ('/usr/bin/ssh -i /data/ssh/replication -o BatchMode=yes'
                  ' -o StrictHostKeyChecking=yes -q')

    if dedicateduser:
        sshcmd = "%s -l %s" % (
            sshcmd,
            dedicateduser.encode('utf-8'),
            )

    if replication.repl_userepl:
        Rflag = '-R '
    else:
        Rflag = ''

    wanted_list = []
    known_latest_snapshot = ''
    expected_local_snapshot = ''
    last_replicated = ''  

    if replication.repl_preservefs:
        recvflag = '-d'
        remotefs_final = "%s%s%s" % (remotefs, localfs.partition('/')[1],localfs.partition('/')[2])
    else:
        recvflag = '-e'
        remotefs_final = "%s/%s" % (remotefs, localfs.rpartition('/')[2])

    # Test if there is work to do, if so, own them
    MNTLOCK.lock()
    log.debug("Checking dataset %s" % (localfs))
    zfsproc = pipeopen('/sbin/zfs list -Ht snapshot -o name,freenas:state -r -d 1 %s' % (localfs), debug)
    output, error = zfsproc.communicate()
    if zfsproc.returncode:
        log.warn('Could not determine last available snapshot for dataset %s: %s' % (
            localfs,
            error,
            ))
        MNTLOCK.unlock()
        continue
    if output != '':
        snapshots_list = output.split('\n')
        snapshots_list.reverse()
        found_latest = False
        for snapshot_item in snapshots_list:
            if snapshot_item != '':
                snapshot, state = snapshot_item.split('\t')
                if found_latest:
                    # assert (known_latest_snapshot != '') because found_latest
                    if state not in ('-','Replicated'):
                        system('/sbin/zfs set freenas:state=NEW %s' % (known_latest_snapshot))
                        system('/sbin/zfs set freenas:state=Latest %s' % (snapshot))
                        wanted_list.insert(0, known_latest_snapshot)
                        log.debug("Snapshot %s added to wanted list (was LATEST)" % (snapshot))
                        known_latest_snapshot = snapshot
                        log.warn("Snapshot %s became latest snapshot" % (snapshot))
                else:
                    log.debug("Snapshot: %s State: %s" % (snapshot, state))
                    if state == 'Latest' and not resetonce:
                        found_latest = True
                        known_latest_snapshot = snapshot
                        log.debug("Snapshot %s is the recorded latest snapshot" % (snapshot))
                    elif state == 'NEW' or resetonce:
                        wanted_list.insert(0, snapshot)
                        log.debug("Snapshot %s added to wanted list" % (snapshot))
                    elif state == 'In_Progress' or resetonce: #If state = In_Progress then there must have been a failure, assume it didn't replicate
                        system('/sbin/zfs set freenas:state=NEW %s' % (snapshot))
                        wanted_list.insert(0, snapshot)
                        log.debug("Snapshot %s was In_Progress added to wanted list" % (snapshot))
                    elif state.startswith('INPROGRESS'):
                        # For compatibility with older versions
                        wanted_list.insert(0, snapshot)
                        system('/sbin/zfs set freenas:state=NEW %s' % (snapshot))
                        log.debug("Snapshot %s added to wanted list (stale)" % (snapshot))
                    elif state  == 'Replicated':
                        # The snapshot is already replicated
                        if last_replicated=='': 
                            last_replicated = snapshot
                            log.debug("Snapshot %s is last replicated" % (snapshot))
                        else:
                           log.debug("Snapshot %s is already replicated" % (snapshot))
                    elif state in('-','Replica'):
                        # The snapshot is not wanted or is not an automated snapshot
                        log.debug("Snapshot %s unwanted" % (snapshot))
                    else:
                        # This should be exception but skip for now.
                        MNTLOCK.unlock()
                        continue
    MNTLOCK.unlock()

    # If there is nothing to do, go through next replication entry
    if len(wanted_list) == 0:
        continue

    # Get list of snapshots on remote filesystem
    rzfscmd = '"zfs list -Hr -o name -t snapshot -d 1 %s | tail -n 1 | cut -d@ -f2"' % (remotefs_final)
    sshproc = pipeopen('%s -p %d %s %s' % (sshcmd, remote_port, remote, rzfscmd))
    output = sshproc.communicate()[0]
   
    if output!='' and not resetonce: 
        # Check if it matches remote snapshot
        expected_local_snapshot = '%s@%s' % (localfs, output.split('\n')[0])
        if expected_local_snapshot == known_latest_snapshot:
            # Accept
            log.debug("Found matching latest snapshot %s remotely" % (known_latest_snapshot))
            last_snapshot = known_latest_snapshot
        else:
            # Do we have last remote snapshot locally? if yes then mark it as Latest and continue
            log.info("Can not locate expected snapshot %s, looking more carefully" % (expected_local_snapshot))
            MNTLOCK.lock()
            zfsproc = pipeopen('/sbin/zfs list -Ht snapshot -o name,freenas:state %s' % (expected_local_snapshot), debug)
            output = zfsproc.communicate()[0]
            if output != '':
                last_snapshot, state = output.split('\n')[0].split('\t')
                log.info("Marking %s as latest snapshot" % (last_snapshot))
                if state in ('-','Replicated'):
                    if known_latest_snapshot !='':
                        system('/sbin/zfs set freenas:state=- %s' % (known_latest_snapshot)) # not exist on remote
                    elif last_replicated !='':
                        system('/sbin/zfs set freenas:state=Latest %s' % (last_replicated))
                    system('/sbin/zfs set freenas:state=Latest %s' % (last_snapshot))
                    known_latest_snapshot = last_snapshot
            else:
                log.warn("Can not locate a proper local snapshot for %s" % (localfs))
                # Can NOT proceed any further.  Report this situation.
                error, errmsg = send_mail(subject="Replication failed!", text=\
                    """
Hello,
    The replication failed for the local ZFS %s because the remote system
    have diverged snapshot with us.
                        """ % (localfs), interval=datetime.timedelta(hours=2), channel='autorepl')
                MNTLOCK.unlock()
                continue
            MNTLOCK.unlock()
    else:
        #There are no remote snapshots
        system('/sbin/zfs inherit -r freenas:state %s' % (localfs))
        known_last_snapshot='' # This will force a non-incremental zfs send resending all local snapshots
    
    if resetonce:
        log.log(logging.NOTICE, "Destroying remote %s" % (remotefs_final))
        destroycmd = '%s -p %d %s /sbin/zfs destroy -rRf %s' % (sshcmd, remote_port, remote, remotefs_final)
        system(destroycmd)
        known_latest_snapshot = ''

    last_snapshot = known_latest_snapshot

    for snapname in wanted_list:
        zfssendlog = '/tmp/zfssendlog-%s' % (snapname.split('@')[1])
        log.debug("Create %s log in tmp for zfs send" % (zfssendlog)) 
        if replication.repl_limit != 0:
            limit = ' | /usr/local/bin/throttle -K %d' % replication.repl_limit
        else:
            limit = ''
        if last_snapshot == '':
            replcmd = '(/sbin/zfs send %s -v %s%s | /bin/dd obs=1m | /bin/dd obs=1m | %s -p %d %s "/sbin/zfs receive -F %s %s && echo Succeeded.") > %s 2>&1' % (Rflag, snapname, limit, sshcmd, remote_port, remote, recvflag, remotefs, zfssendlog)
        else:
            replcmd = '(/sbin/zfs send %s -v -I %s %s%s | /bin/dd obs=1m | /bin/dd obs=1m | %s -p %d %s "/sbin/zfs receive -F %s %s && echo Succeeded.") > %s 2>&1' % (Rflag, last_snapshot, snapname, limit, sshcmd, remote_port, remote, recvflag, remotefs, zfssendlog)
        system('/sbin/zfs set freenas:state="In_Progress" %s' % (snapname))
        system(replcmd)

        msgproc = pipeopen('tail -n 1 %s' % (zfssendlog))
        msg = msgproc.communicate()[0]
        fullmsg = ''
        if not msg.startswith('Succeeded'):
            with open(zfssendlog) as f:
                fullmsg = f.read()
        os.remove(zfssendlog)
        log.debug("Replication result: %s" % (msg))

        # Determine if the remote side have the snapshot we have now.
        rzfscmd = '"zfs list -Hr -o name -t snapshot -d 1 %s | tail -n 1 | cut -d@ -f2"' % (remotefs_final)
        sshproc = pipeopen('%s -p %d %s %s' % (sshcmd, remote_port, remote, rzfscmd))
        output = sshproc.communicate()[0]
        if output != '':
            expected_local_snapshot = '%s@%s' % (localfs, output.split('\n')[0])
            if expected_local_snapshot == snapname:
                # Replication was successful, mark as such
                MNTLOCK.lock()
                if last_snapshot != '':
                    system('/sbin/zfs set freenas:state=Replicated %s' % (last_snapshot))
                    system('%s -p %d %s "/sbin/zfs set freenas:state=Replica %s@%s"' % (sshcmd, remote_port, remote, remotefs_final, last_snapshot.split('@')[1]))
                last_snapshot = snapname
                system('/sbin/zfs set freenas:state=Latest %s' % (snapname))
                system('%s -p %d %s "/sbin/zfs set freenas:state=Latest_Replica %s@%s"' % (sshcmd, remote_port, remote, remotefs_final, snapname.split('@')[1]))
                MNTLOCK.unlock()
                replication.repl_lastsnapshot = last_snapshot # TODO check if there is any merit retaining this field 
                if resetonce:
                    replication.repl_resetonce = False
                replication.save()
                continue
            else:
                log.warn("Remote and local mismatch after replication: %s@%s vs %s" % (remotefs_final, output.split('\n')[0], snapname))
                if msg.startswith ('Succeeded'): # The replication appears to have succeeded, let's investigate further  
                    rzfscmd = '"zfs list -Ho name -t snapshot -d 1 %s@%s | cut -d@ -f2"' % (remotefs_final, snapname.split('@')[1])
                    sshproc = pipeopen('%s -p %d %s %s' % (sshcmd, remote_port, remote, rzfscmd))
                    output = sshproc.communicate()[0]
                    if output != '':  #Replicated snapshot exists on remote system so was successful 
                        log.warn("Snapshot %s already exist on remote, marking as such" % (snapname.split('@')[1]))
                        MNTLOCK.lock()
                        if last_snapshot != '':
                            system('/sbin/zfs set freenas:state=Replicated %s' % (last_snapshot))
                            system('%s -p %d %s "/sbin/zfs set freenas:state=Replica %s@%s"' % (sshcmd, remote_port, remote, remotefs_final, last_snapshot.split('@')[1]))
                        last_snapshot=snapname
                        system('/sbin/zfs set freenas:state=Latest %s' % (snapname))
                        system('%s -p %d %s "/sbin/zfs set freenas:state=Latest_Replica %s@%s"' % (sshcmd, remote_port, remote, remotefs_final, snapname.split('@')[1]))
                        replication.repl_lastsnapshot = last_snapshot # TODO check if there is any merit retaining this field
                        if resetonce:
                            replication.repl_resetonce = False
                        replication.save()

                        MNTLOCK.unlock()
                        continue

                    else:
                        system('/sbin/zfs set freenas:state=NEW %s' % (snapname)) 
                        replicatedfailed=True
                else:
                    system('/sbin/zfs set freenas:state=NEW %s' % (snapname)) 
                    replicationfailed = True
        else:
            replicationfailed = True

        if replicationfailed == True:
            # Something wrong, report.
            log.warn("Replication of %s failed with %s" % (snapname, msg))
            error, errmsg = send_mail(subject="Replication failed!", text=\
            """
Hello,
    The system was unable to replicate snapshot %s to %s
======================
%s
            """ % (localfs, remote, fullmsg), interval=datetime.timedelta(hours=2), channel='autorepl')
            break

os.remove('/var/run/autorepl.pid')
log.debug("Autosnap replication finished")
