# Copyright (C) 2017 Menlo Security

import logging
import time

from proxmoxer import ProxmoxAPI, ResourceException

from cuckoo.common.abstracts import Machinery
from cuckoo.common.config import config
from cuckoo.common.exceptions import CuckooCriticalError
from cuckoo.common.exceptions import CuckooMachineError

log = logging.getLogger(__name__)

class Proxmox(Machinery):
    """Manage Proxmox sandboxes."""
    def __init__(self):
        super(Proxmox, self).__init__()
        self.node = None
        self.vm = None
        self.timeout = config("cuckoo:timeouts:vm_state")

    def _initialize_check(self):
        """Ensures that credentials have been entered into the config file.
        @raise CuckooCriticalError: if no credentials were provided
        """
        # TODO This should be moved to a per-machine thing.
        if not self.options.proxmox.username or not self.options.proxmox.password:
            raise CuckooCriticalError(
                "Proxmox credentials are missing, please add them to "
                "the Proxmox machinery configuration file."
            )
        if not self.options.proxmox.hostname:
            raise CuckooCriticalError("Proxmox hostname not set")

        super(Proxmox, self)._initialize_check()

    def find_vm(self, label):
        proxmox = ProxmoxAPI(self.options.proxmox.hostname,
                             user=self.options.proxmox.username,
                             password=self.options.proxmox.password,
                             verify_ssl=False)

        # /cluster/resources[type=vm] will give us all VMs no matter which node
        # they reside on
        try:
            vms = proxmox.cluster.resources.get(type="vm")
        except ResourceException as e:
            raise CuckooMachineError("Error enumerating VMs: %s" % e)

        for vm in vms:
            if vm["name"] == label:
                # dynamically address
                # /nodes/<node>/{qemu,lxc,openvz,...}/<vmid> to get handle on
                # VM
                node = proxmox.nodes(vm["node"])
                hv = node.__getattr__(vm["type"])
                vm = hv.__getattr__(str(vm["vmid"]))

                # remember various request proxies for subsequent actions
                self.node = node
                self.vm = vm
                return

        raise CuckooMachineError("Not found")

    def wait_for_task(self, taskid):
        elapsed = 0
        while elapsed < self.timeout:
            try:
                task = self.node.tasks(taskid).status.get()
            except ResourceException as e:
                raise CuckooMachineError("Error getting status of task "
                                         "%s: %s" % (taskid, e))

            if task["status"] == "stopped":
                return task

            log.debug("Waiting for task %s to finish: %s", taskid, task)
            time.sleep(1)
            elapsed += 1

        return None

    def find_snapshot(self, label):
        snapshot = self.db.view_machine_by_label(label).snapshot
        if snapshot:
            return snapshot

        log.debug("No snapshot configured for VM %s, determining most recent "
                  "one", label)
        try:
            snapshots = self.vm.snapshot.get()
        except ResourceException as e:
            raise CuckooMachineError("Error enumerating snapshots: %s" % e)

        snaptime = 0
        snapshot = None
        for snap in snapshots:
            # ignore "meta-snapshot" current which is the current state
            if snap["name"] == "current":
                continue

            if snap["snaptime"] > snaptime:
                snaptime = snap["snaptime"]
                snapshot = snap["name"]

        return snapshot

    def rollback(self, label):
        snapshot = self.find_snapshot(label)
        if not snapshot:
            raise CuckooMachineError("No snapshot found - check config")

        try:
            log.debug("Reverting VM %s to snapshot %s", label, snapshot)
            taskid = self.vm.snapshot(snapshot).rollback.post()
        except ResourceException as e:
            raise CuckooMachineError("Couldn't trigger rollback to "
                                     "snapshot %s: %s" % (snapshot, e))

        task = self.wait_for_task(taskid)
        if not task:
            raise CuckooMachineError("Timeout expired while rolling back to "
                                     "snapshot %s" % snapshot)
        if task["exitstatus"] != "OK":
            raise CuckooMachineError("Rollback to snapshot %s failed: %s"
                                     % (snapshot, task["exitstatus"]))

    def start(self, label, task):
        self.find_vm(label)
        self.rollback(label)

        try:
            status = self.vm.status.current.get()
        except ResourceException as e:
            raise CuckooMachineError("Couldn't get status: %s" % e)

        if status["status"] == "running":
            log.debug("VM already running after rollback, no need to start it")
            return

        try:
            log.debug("Starting VM %s", label)
            taskid = self.vm.status.start.post()
        except ResourceException as e:
            raise CuckooMachineError("Couldn't trigger start: %s" % e)

        task = self.wait_for_task(taskid)
        if not task:
            raise CuckooMachineError("Timeout expired while starting")
        if task["exitstatus"] != "OK":
            raise CuckooMachineError("Start failed: %s" % task["exitstatus"])

    def stop(self, label):
        self.find_vm(label)

        try:
            log.debug("Stopping VM %s", label)
            taskid = self.vm.status.stop.post()
        except ResourceException as e:
            raise CuckooMachineError("Couldn't trigger stop: %s" % e)

        task = self.wait_for_task(taskid)
        if not task:
            raise CuckooMachineError("Timeout expired while stopping")
        if task["exitstatus"] != "OK":
            raise CuckooMachineError("Stop failed: %s" % task["exitstatus"])
