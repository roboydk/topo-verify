## topo-verify
Low level Topology verification using Packet injection.


### How to use it:

1. Clone the repo.

> git clone https://github.com/roboydk/topo-verify.git

2. Spin up the vagrant file

> cd topo-verify/python/
> vagrant up

3. Apply the ansible playbook

> cd topo-verify/ansible
> ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook playbooks/eline.yml -i ansible_hosts

4. Execute the python script

> python topo-verifier.py

You will have output of all available devices and will have list of devices with connection issue in between. 
