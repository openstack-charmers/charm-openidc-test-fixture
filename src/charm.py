#!/usr/bin/env python3
# Copyright 2022 ubuntu
# See LICENSE file for licensing details.
#
# Learn more at: https://juju.is/docs/sdk

"""Charm the service.

Refer to the following post for a quick-start guide that will help you
develop a new k8s charm using the Operator Framework:

    https://discourse.charmhub.io/t/4208
"""

import docker
import logging

from ops.charm import CharmBase
from ops.framework import StoredState
from ops.main import main
from ops.model import (
    MaintenanceStatus,
    ActiveStatus,
    BlockedStatus
)
from charmhelper import (
    apt_update, apt_install)
import subprocess
logger = logging.getLogger(__name__)

class FixtureCharmFailedInstallation(Exception):

    def __init__(self,
                 message="An error occurred during installation: {}",
                 error=""):
        super().__init__(message.format(error))

class CharmOpenidcTestFixtureCharm(CharmBase):
    """Charm the service."""

    _stored = StoredState()

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.install, self._on_install)

    def _on_install(self, event):
        """Run the installation process.
        There are several options for installation, depending on distro.
        """
        self.model.unit.status = MaintenanceStatus("Installing packages...")
        apt_update()
        apt_install(["docker.io"])
        client = docker.from_env()
        try:
            # Fetch a resource and install the dockerfile
            resource = self.model.resources.fetch("dockerimg")
            with open(resource, 'rb') as f:
                client.images.load(f)
        except subprocess.CalledProcessError as e:
            raise FixtureCharmFailedInstallation(
                error=str(e))
        except Exception:
            # Failed to find a resource
            resource = None

        container = client.containers.run(client.images.list()[0].id,
                            detach=True, ports={"8080":"8080"}, command="start-dev")
        if container.status == 'created':
            self.model.unit.status = ActiveStatus("Service is running")



if __name__ == "__main__":
    main(CharmOpenidcTestFixtureCharm)
