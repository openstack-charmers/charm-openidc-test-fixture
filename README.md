# charm-openidc-test-fixture

## Create the keycloak docker image resource

Install docker package:

```
sudo apt install docker.io
```
Create the charm resource

```
sudo docker pull quay.io/keycloak/keycloak:18.0.0
sudo docker images
sudo docker save <img id> | gzip > keycloak.tar.gz
```

Attach the resource to the charm

```
juju deploy ./charm-openidc-test-fixture_ubuntu-20.04-amd64.charm --resource dockerimg=../keyclok.tar.gz
```

Access the keycloack dashboard using port 8080

```
curl http://10.248.246.178:8080
``
