# charm-openidc-test-fixture

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

Access the keycloack dashboard using port 8080

```
curl -k https://10.248.246.178:443
```

The realm is `demorealm`.

The users are:

    johndoe
    janedoe

The password for each is 'crapper'.

