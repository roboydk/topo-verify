## topo-verify
Low level Topology verification using Packet injection.


### How to use it:

- Clone the repo.

```
git clone https://github.com/roboydk/topo-verify.git
```

- Spin up the vagrant file

```shell
cd topo-verify/python/
vagrant up
```

- Apply the ansible playbook

```shell
cd topo-verify/ansible
ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook playbooks/eline.yml -i ansible_hosts
```

- Execute the python script

```shell
python topo-verifier.py
```

You will have output of all available devices and will have list of devices with connection issue in between. 
