# OpenIDC Test Fixture

## Create the keycloak docker image resource

Install docker package:

```
sudo apt install docker.io
```
Create the charm resource

```
docker build . -t keycloak-test
docker save keycloak-test | gzip > keycloak.tar.gz
```

Attach the resource to the charm

```
juju deploy ./charm-openidc-test-fixture_ubuntu-20.04-amd64.charm --resource dockerimg=./keycloak.tar.gz
```

When deploying from charmhub a default docker image is used when not attached
one explicitly:

```
juju deploy --channel latest/edge ch:openidc-test-fixture
```

Access the keycloak dashboard using port 8080

```
xdg-open http://<IP>:8080/admin
```

When related to vault the service is reconfigured to use HTTPS, be aware that
all the data will be purged before the reconfiguration.

```
juju add-relation vault openidc-test-fixture
```

The realm is `demorealm`.

The users are:

    johndoe
    janedoe

The password for each is 'f00bar'.

The clients are:

    keystone

The password for each client is 'ubuntu11'
