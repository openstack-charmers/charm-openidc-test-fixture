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

import json
import logging
import os
import re
import subprocess

import docker

from ops.charm import CharmBase
from ops.framework import StoredState
from ops.main import main
from ops.model import (
    MaintenanceStatus,
    ActiveStatus,
    WaitingStatus,
)
from charmhelpers.contrib.openstack.cert_utils import (
    get_certificate_request,
    install_certs,
)
from charmhelpers.core.hookenv import (
    open_port,
    unit_public_ip,
)
from charmhelpers.core.host import (
    ca_cert_absolute_path,
    install_ca_cert,
)
from charmhelpers.fetch import (
    apt_update, apt_install
)

logger = logging.getLogger(__name__)

CONTAINER_NAME = "openidc-test-fixture"
SSL_DIR = '/etc/ssl/'
SOURCE_JAVA_KEYSTORE = '/etc/ssl/certs/java/cacerts'
TARGET_JAVA_KEYSTORE = '/etc/x509/https/keystore.ks'
JAVA_KEYSTORE_PASSWORD = 'changeit'  # Debian's default password
TARGET_CERT_CRT_PATH = '/etc/x509/https/tls.crt'
TARGET_CERT_KEY_PATH = '/etc/x509/https/tls.key'
TARGET_CA_CERT_PATH = '/etc/x509/https/ca.crt'
USERS = [('johndoe', 'f00bar'),
         ('janedoe', 'f00bar')]
CLIENTS = [('keystone', 'ubuntu11')]
CMD_START = ('start '
             '--hostname {IP_ADDRESS} '
             '--https-certificate-file {CERT_CRT} '
             '--https-certificate-key-file {CERT_KEY} '
             '--https-trust-store-file={JAVA_KEYSTORE} '
             '--https-trust-store-password={KEYSTORE_PASSWORD}')
CMD_CREATE_REALM = ('/opt/keycloak/bin/kcadm.sh create '
                    '--server {} '
                    '--realm master  --user admin '
                    '--password admin realms '
                    '-s realm=demorealm -s enabled=true -o '
                    '--trustpass changeit')
CMD_CREATE_USER = ('/opt/keycloak/bin/kcadm.sh create '
                   '--server {} '
                   '--realm master  --user admin '
                   '--password admin users '
                   '-s username={} -s enabled=true '
                   '-r demorealm '
                   '--trustpass changeit')
CMD_SET_PASSWORD = ('/opt/keycloak/bin/kcadm.sh set-password '
                    '--server {} '
                    '--realm master  --user admin '
                    '--password admin   --username {} '
                    '-r demorealm --new-password {} '
                    '--trustpass changeit')
CMD_CONFIG_TRUSTSTORE = ('/opt/keycloak/bin/kcadm.sh config truststore '
                         '--storepass {} {}')
CMD_CREATE_CLIENT = ('/opt/keycloak/bin/kcadm.sh create clients '
                     '-s clientId={} '
                     '-s secret={} '
                     '-s enabled=true '
                     '-s implicitFlowEnabled=true '
                     '-s directAccessGrantsEnabled=true '
                     '-s serviceAccountsEnabled=true '
                     '--server {} --realm master --user admin '
                     '--password admin  -r demorealm --trustpass changeit')


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
        self.framework.observe(self.on.certificates_relation_joined,
                               self._on_certificates_relation_joined)
        self.framework.observe(self.on.certificates_relation_changed,
                               self._on_certificates_relation_changed)

    def _on_install(self, event):
        """Run the installation process.
        There are several options for installation, depending on distro.
        """
        self.model.unit.status = MaintenanceStatus("Installing packages...")
        apt_update()
        apt_install(["docker.io", "openjdk-11-jre-headless", ], fatal=True)
        client = docker.from_env()

        self.model.unit.status = MaintenanceStatus(
            "Packages installed. Preparing container..."
        )
        try:
            self.model.unit.status = MaintenanceStatus(
                "Loading container image..."
            )
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
        self._stop_container(client, remove=True)
        container = self._start_container(client)
        self._stored.container_id = container.id
        logger.info('Container %s status: %s', container.id, container.status)
        self.model.unit.status = WaitingStatus("Waiting for HTTP service")
        self._wait_for_http("http://localhost:8080")
        open_port(8080)
        self._configure_idp(container)

        if container.status == 'created':
            self.model.unit.status = ActiveStatus("Ready")

        cmd = '/opt/keycloak/bin/kc.sh --version'
        (exit_code, output) = container.exec_run(cmd)
        m = re.match('^Keycloack (\S+)\n.*', output.decode('utf-8'),
                     re.MULTILINE)
        if m:
            self.unit.set_workload_version(m.group(1))

    def _wait_for_http(self, url):
        subprocess.check_call(["./src/wait_for_tcp_port.sh", url])

    def _configure_idp(self, container, url='http://localhost:8080'):
        logger.info('Creating realm')
        cmd = CMD_CREATE_REALM.format(url)
        logger.debug('cmd: %s', cmd)
        (exit_code, output) = container.exec_run(cmd=cmd)
        logger.debug('exit code: %s, output: %s', exit_code, output)
        if exit_code != 0:
            logger.error('Cannot create realm: %s', output)
            raise Exception(output)

        for username, password in USERS:
            logger.info('Creating user: %s', username)
            cmd = CMD_CREATE_USER.format(url, username)
            logger.debug('cmd: %s', cmd)
            (exit_code, output) = container.exec_run(cmd=cmd)
            logger.debug('exit code: %s, output: %s', exit_code, output)
            if exit_code != 0:
                logger.error('Cannot create user: %s', output)
                raise Exception(output)

            logger.info('Setting password for user: %s', username)
            cmd = CMD_SET_PASSWORD.format(url, username, password)
            logger.debug('cmd: %s', cmd)
            (exit_code, output) = container.exec_run(cmd=cmd)
            logger.debug('exit code: %s, output: %s', exit_code, output)
            if exit_code != 0:
                logger.error('Cannot set password: %s', output)
                raise Exception(output)

        for client, secret in CLIENTS:
            logger.info('Creating client: %s', client)
            cmd = CMD_CREATE_CLIENT.format(client, secret, url)
            logger.debug('cmd: %s', cmd)
            (exit_code, output) = container.exec_run(cmd=cmd)
            logger.debug('exit code: %s, output: %s', exit_code, output)
            if exit_code != 0:
                logger.error('Cannot create client: %s', output)
                raise Exception(output)

    def _on_certificates_relation_joined(self, event):
        try:
            logger.info('Requesting a certificate')
            relation = self.model.get_relation('certificates')
            cert_req = get_certificate_request()
            logger.debug('Certificate request: %s', cert_req)
            data = relation.data[self.unit]
            for key, value in cert_req.items():
                data[key] = value
        except Exception:
            logger.exception('Failed to request certificates, deferring.')
            event.defer()
            return

    def _on_certificates_relation_changed(self, event):
        try:
            name = self.unit.name.replace('/', '_')
            data = event.relation.data[event.unit]
            certs = data.get('{}.processed_requests'.format(name))
            chain = data.get('chain')
            ca = data.get('ca')
            if certs:
                certs = json.loads(certs)
            else:
                logger.debug('There are no certs yet')
                return

            self.model.unit.status = WaitingStatus("Configuring certificates")
            install_certs(SSL_DIR, certs, chain)
            # the name of the generated certificates is cert_{cn} and key_{cn}
            # while 'cn' is the key of the `cert` dict.
            cn = list(certs.keys())[0]
            cert_crt_path = os.path.join(SSL_DIR, 'cert_{}'.format(cn))
            cert_key_path = os.path.join(SSL_DIR, 'key_{}'.format(cn))
            cert_name = 'juju-{}'.format(self.unit.app.name)
            install_ca_cert(ca, cert_name)
            ca_cert_path = ca_cert_absolute_path(cert_name)
            mounts = [
                docker.types.Mount(source=cert_crt_path,
                                   target=TARGET_CERT_CRT_PATH,
                                   type='bind'),
                docker.types.Mount(source=cert_key_path,
                                   target=TARGET_CERT_KEY_PATH,
                                   type='bind'),
                docker.types.Mount(source=ca_cert_path,
                                   target=TARGET_CA_CERT_PATH,
                                   type='bind'),
                docker.types.Mount(source=SOURCE_JAVA_KEYSTORE,
                                   target=TARGET_JAVA_KEYSTORE,
                                   type='bind'),
            ]
            env = {'X509_CA_BUNDLE': TARGET_CA_CERT_PATH}
            client = docker.from_env()

            # we remove the container to re-bootstrap with TLS support.
            self._stop_container(client, remove=True)
            cmd = CMD_START.format(
                IP_ADDRESS=unit_public_ip(),
                CERT_CRT=TARGET_CERT_CRT_PATH,
                CERT_KEY=TARGET_CERT_KEY_PATH,
                JAVA_KEYSTORE=TARGET_JAVA_KEYSTORE,
                KEYSTORE_PASSWORD=JAVA_KEYSTORE_PASSWORD,
            )
            container = self._start_container(client, cmd,
                                              mounts=mounts,
                                              env=env)
            url = "https://{}:8443".format(unit_public_ip())
            self.model.unit.status = WaitingStatus("Waiting for HTTPS service")
            self._wait_for_http(url)
            open_port(8443)
            logger.info('Container %s status: %s',
                        container.short_id, container.status)
            self.model.unit.status = WaitingStatus("Configuring the service")
            self._add_truststore(container)
            self._configure_idp(container, url)
            self.model.unit.status = ActiveStatus("Ready")

        except Exception:
            logger.exception('Failed to process certificate requests')
            event.defer()
            return

    def _add_truststore(self, container):
        logger.info('Adding system java keystore to the service')
        cmd = CMD_CONFIG_TRUSTSTORE.format(JAVA_KEYSTORE_PASSWORD,
                                           TARGET_JAVA_KEYSTORE)
        logger.debug('cmd: %s', cmd)
        (exit_code, output) = container.exec_run(cmd=cmd)
        logger.debug('exit code: %s, output: %s', exit_code, output)
        if exit_code != 0:
            logger.error('Cannot add trusted keystore: %s', output)
            raise Exception(output)

    def _stop_container(self, client, remove=False):
        for container in client.containers.list():
            if container.name == CONTAINER_NAME:
                logger.info('Stopping container %s(%s)',
                            container.name, container.short_id)
                container.stop()
                if remove:
                    logger.info('Removing container %s(%s)',
                                container.name, container.short_id)
                    container.remove()

    def _start_container(self, client, cmd="start-dev", mounts=None, env=None):
        environment = {"KEYCLOAK_ADMIN": "admin",
                       "KEYCLOAK_ADMIN_PASSWORD": "admin"}
        if env:
            environment.update(env)

        logger.info('Starting container with command: %s, env %s',
                    cmd, environment)
        container = client.containers.run(
            client.images.list()[0].id, cmd,
            name=CONTAINER_NAME,
            detach=True, ports={"8080": "8080",
                                "8443": "8443"},
            environment=environment,
            mounts=mounts,
        )
        return container


if __name__ == "__main__":
    main(CharmOpenidcTestFixtureCharm)
