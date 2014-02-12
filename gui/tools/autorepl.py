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

# NOTE THIS CHANGSET IS TO SHOW THINKING - IT IS NOT TESTED

import datetime
import logging
import os
import sys

sys.path.extend([
    '/usr/local/www',
    '/usr/local/www/freenasUI',
])

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'freenasUI.settings')

# Make sure to load all modules
from django.db.models.loading import cache
cache.get_apps()

from freenasUI.freeadmin.apppool import appPool
from freenasUI.storage.models import Replication
from freenasUI.common.timesubr import isTimeBetween
from freenasUI.common.pipesubr import pipeopen, system
from freenasUI.common.locks import mntlock
from freenasUI.common.system import send_mail

# DESIGN NOTES
#
# A snapshot can have the following freenas:state values:
#   Queued          A snapshot which has been queued for replication
#   In_Progress     A snapshot which is in the process of being replicated
#   Replicated      A snapshot which has been replicated to a remote system
#   Failed          A snapshot where replication attempt failed
#   -               A snapshot which has no involvement in the replication process

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

appPool.hook_tool_run('autorepl')

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

    if not replication.repl_enabled:
        log.warn("%s replication not enabled" % replication)
        continue

    remote = replication.repl_remote.ssh_remote_hostname.__str__()
    remote_port = replication.repl_remote.ssh_remote_port
    dedicateduser = replication.repl_remote.ssh_remote_dedicateduser
    fast_cipher = replication.repl_remote.ssh_fast_cipher
    remotefs = replication.repl_zfs.__str__()
    basefs = replication.repl_filesystem.__str__()
    resetonce = replication.repl_resetonce
    replcompresss = replication.repl_compression.__str__()

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

    if replication.repl_recurse:
       Recurseflag = '-r'
    else:
       Recurseflag = ''

    if replication.repl_preservefs:
        recvflag = '-d '
    else:
        recvflag = '-e '

#TODO Add lZ4 compression option when lz4c executable is available
    if replcompression == 'gzip':
        compress = ' | /usr/bin/gzip '
        decompress = ' /usr/bin/gzcat | '
    elif replcompress == 'xz':
        compress = ' | /usr/bin/xz '
        decompress = ' /usr/bin/xzcat | '
    else: # default 'off'
        compress = ''
        decompress = ''


    # Test if there is work to do, if so, own them
    zfsproc = pipeopen('/sbin/zfs list %s -Ho name %s' % (Recurseflag, basefs)) # default order is descending into filesystem from zpool ie Vol1; Vol1/Data1; Vol1/Data1/Data2
    fs = zfsproc.communicate()[0].split('\n')
    for localfs in fs:
        if localfs !='':
            last_snapshot = ''
            output = ''
            remoteoutput = ''
            error = ''
            wanted_list = []
            known_latest_snapshot = ''
            expected_latest_snapshot = ''
            expected_local_snapshot = ''
            replicationfailed = False
            if replication.repl_preservefs:
                remotefs_final = "%s%s%s" % (remotefs, localfs.partition('/')[1],localfs.partition('/')[2])
            else:
                remotefs_final = "%s/%s" % (remotefs, localfs.rpartition('/')[2])

            MNTLOCK.lock()
            log.debug("Checking dataset %s" % (localfs))
            zfsproc = pipeopen('/sbin/zfs list -Ht snapshot -d1 %s' % (localfs), debug)
            output, error = zfsproc.communicate()
            if zfsproc.returncode:
                log.warn('Could not determine local snapshots for dataset %s, error: %s' % (localfs, error))
                MNTLOCK.unlock()
                err, errmsg = send_mail(subject="Replication failed!", text=\
                    """
Hello,

Could not determine local snapshots for dataset %s
======================
%s
                    """ % (localfs, error), interval=datetime.timedelta(hours=2), channel='autorepl')
                continue

            if output != '':
                snapshots_list = output.split('\n')
                snapshots_list.reverse()
                if not resetonce:
                    # Find last snapshot on remote server
                    rzfscmd = '"zfs list -H -o name -t snapshot -d1 %s | tail -n 1 | cut -d@ -f2"' % (remotefs_final)
                    sshproc = pipeopen('%s -p %d %s %s' % (sshcmd, remote_port, remote, rzfscmd))
                    remoteoutput, error = sshproc.communicate()
                    if sshproc.returncode: # can't find last snapshot, check if remote filesystem is available
                        rzfscmd = '"zfs list -Ho name %s"' % (remotefs)
                        sshproc = pipeopen('%s -p %d %s %s' % (sshcmd, remote_port, remote, rzfscmd))
                        remoteoutput, error = sshproc.communicate()
                        if sshproc.returncode: # remote filesystem is NOT available
                            log.warn ("Could not connect to replication filesystem %s on server %s, error: %s" %(remotefs, remote, error))
                            MNTLOCK.unlock()
                            err, errmsg = send_mail(subject="Replication failed!", text=\
                                """
Hello,

Could not connect to replication filesystem %s on server %s.
======================
%s
                                """ % (remotefs, remote, error), interval=datetime.timedelta(hours=2), channel='autorepl')
                            continue
                        else:
                           expected_latest_snapshot =''
                    else:
                        expected_latest_snapshot = '%s@%s' % (localfs, remoteoutput.split('\n')[0])


                for snapshot_item in snapshots_list:
                    if snapshot_item != '':
                        snapshot, state = snapshot_item.split('\t')
                        if resetonce:
                            system('/sbin/zfs set freenas:state=Queued %s' % (snapshot))
                            system('/sbin/zfs hold repl %s' % (snapshot))
                            wanted_list.insert(0,snapshot)
                            log.debug("Snapshot %s added to wanted list" % (snapshot))
                        elif snapshot == expected_latest_snapshot:
                            known_latest_snapshot = snapshot
                            if state != 'Replicated':
                                system('/sbin/zfs set freenas:state=Replicated %s' % (snapshot))
                        elif known_latest_snapshot == '':
                            wanted_list.insert(0,snapshot)
                            log.debug("Snapshot %s added to wanted list" % (snapshot))
                        else:
                            if state != 'Replicated':
                                system('/sbin/zfs inherit freenas:state %s' % (snapshot))
                            log.debug("Snapshot %s not needed for replication" % (snapshot))

                if known_latest_snapshot == '' and not resetonce:
                    log.warn("Latest snapshot %s on remote server is not on local server. Error: %s" % (remoteoutput.split('\n')[0], error))
                    MNTLOCK.unlock()
                    err, errmsg = send_mail(subject="Replication failed!", text=\
                        """
Hello,

Latest snapshot %s on remote server %s can not be found on local server.
======================
%s
                        """ % (remoteoutput.split('\n')[0], remote, error), interval=datetime.timedelta(hours=2), channel='autorepl')
                    continue


            MNTLOCK.unlock()

            # If there is nothing to do, go through next replication entry
            if len(wanted_list) == 0:
                continue

            if resetonce:  #TO DO More validation needed here including recurse options and performance do we need to do rm -rf on base fs
                log.warn("Destroying remote %s snapshots onm remote server %s" % (remotefs_final, remote))
                known_latest_snapshot = ''
                sshproc = pipeopen('%s -p %d %s %s' % (sshcmd, remote_port, remote, rzfscmd))
                system ('%s -p %d %s /sbin/zfs list -Ho name -t snapshot -d1 %s | xargs -n1 /sbin/zfs release repl' % (sshcmd, remote_port, remote, remotefs_final)) #Should we check if there is a hold first before release?
                system ('%s -p %d %s /sbin/zfs list -Ho name -t snapshot -d1 %s | xargs -n1 /sbin/zfs destroy -d' % (sshcmd, remote_port, remote, remotefs_final))


            last_snapshot = known_latest_snapshot

            for snapname in wanted_list:
                zfssendlog = '/tmp/zfssendlog-%s' % (snapname.replace("/","_"))
                log.debug("Create %s log in tmp for zfs send" % (zfssendlog))
                if replication.repl_limit != 0:
                    limit = ' | /usr/local/bin/throttle -K %d' % replication.repl_limit
                else:
                    limit = ''

                if last_snapshot == '':
                    replcmd = '(/sbin/zfs send -V %s%s%s%s | /bin/dd obs=1m | /bin/dd obs=1m | %s -p %d %s "%s/sbin/zfs receive -F %s%s && echo Succeeded.") > %s 2>&1' % (Rflag, snapname, compress, limit, sshcmd, remote_port, remote, decompress, recvflag, remotefs, zfssendlog)
                else:
                    replcmd = '(/sbin/zfs send -V %s-I %s %s%s%s | /bin/dd obs=1m | /bin/dd obs=1m | %s -p %d %s "%s/sbin/zfs receive -F %s%s && echo Succeeded.") > %s 2>&1' % (Rflag, last_snapshot, snapname, compress, limit, sshcmd, remote_port, remote, decompress, recvflag, remotefs, zfssendlog)

                system('/sbin/zfs set freenas:state="In_Progress" %s' % (snapname))  #Strictly speaking not needed as can see which snapshot is currently replicating from sendlog and proc list (which also shows % transferred now) but this brings status info together in one field
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
                rzfscmd = '"zfs list -Ho name -t snapshot -d1 %s@%s | cut -d@ -f2"' % (remotefs_final, snapname.split('@')[1])
                sshproc = pipeopen('%s -p %d %s %s' % (sshcmd, remote_port, remote, rzfscmd))
                output, error = sshproc.communicate()
                if sshproc.returncode:
                    log.warn('Could not determine remote snapshots %s for dataset %s: %s' % (remotefs_final, localfs, error))
                    system('/sbin/zfs set freenas:state=Failed %s' % (snapname))
                    replicationfailed = True
                if output != '':
                    expected_local_snapshot = '%s@%s' % (localfs, output.split('\n')[0])
                    if expected_local_snapshot == snapname:
                        # Replication was successful, mark as such
                        MNTLOCK.lock()
                        if last_snapshot != '':
                            system('/sbin/zfs release repl %s' % (last_snapshot))
                            system('%s -p %d %s "/sbin/zfs release repl  %s@%s"' % (sshcmd, remote_port, remote, remotefs_final, last_snapshot.split('@')[1]))
                        system('/sbin/zfs set freenas:state=Replicated %s' % (snapname))
                        system('%s -p %d %s "/sbin/zfs hold repl %s@%s"' % (sshcmd, remote_port, remote, remotefs_final, snapname.split('@')[1]))
                        last_snapshot = snapname
                        MNTLOCK.unlock()
                        if resetonce:
                            replication.repl_resetonce = False
                        continue

                else:
                    system('/sbin/zfs set freenas:state=Failed %s' % (snapname))
                    replicationfailed = True

                if replicationfailed == True:
                    # Something wrong, report.
                    log.warn("Replication of %s failed with %s" % (snapname, msg))
                    MNTLOCK.unlock()
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