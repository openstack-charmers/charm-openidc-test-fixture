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
from charmhelpers.fetch import (
    apt_update, apt_install
)
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

        self.model.unit.status = MaintenanceStatus("Packages installed. Preparing container...")
        try:
            self.model.unit.status = MaintenanceStatus("Loading container image...")
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
        self.model.unit.status = MaintenanceStatus("Running container...")
        container = client.containers.run(client.images.list()[0].id,
                detach=True, ports={"8443":"443"}, environment={"KEYCLOAK_ADMIN":"admin","KEYCLOAK_ADMIN_PASSWORD":"admin"})
        rc = subprocess.call("./src/wait_for_tcp_port.sh", shell=True)
        container.exec_run(cmd='/opt/keycloak/bin/kcadm.sh create --server http://localhost:8080 --realm master  --user admin --password admin realms -s realm=demorealm -s enabled=true -o')
        container.exec_run(cmd='/opt/keycloak/bin/kcadm.sh create --server http://localhost:8080 --realm master  --user admin --password admin users -s username=johndoe -s enabled=true -r demorealm')
        container.exec_run(cmd='/opt/keycloak/bin/kcadm.sh create --server http://localhost:8080 --realm master  --user admin --password admin users -s username=janedoe -s enabled=true -r demorealm')
        container.exec_run(cmd='/opt/keycloak/bin/kcadm.sh set-password --server http://localhost:8080 --realm master  --user admin --password admin   --username janedoe -r demorealm --new-password crapper')
        container.exec_run(cmd='/opt/keycloak/bin/kcadm.sh set-password --server http://localhost:8080 --realm master  --user admin --password admin   --username johndoe -r demorealm --new-password crapper')
        #container.restart()
        if container.status == 'created':
            self.model.unit.status = ActiveStatus("Service is running")



if __name__ == "__main__":
    main(CharmOpenidcTestFixtureCharm)
