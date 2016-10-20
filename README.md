# topo-verify

Low level Topology verification using Packet injection.

## Requirements

- Minimum 2 VM to start (1gb of RAM) in Vagrant and Vagrant itself.
- The following Python dependencies `pip install paramiko networkx pyyaml`.

## How to use it:

- Clone the repo.

```
git clone https://github.com/roboydk/topo-verify.git
```

- Spin up the vagrant file

```shell
cd topo-verify/python && vagrant up
```

- Apply the ansible playbook

```shell
cd ../ansible && ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook playbooks/eline.yml -i ansible_hosts
```

- Execute the python script

```shell
cd ../python && python topo_verifier.py
```

You will have output of all available devices and will have list of devices with connection issue in between.

- Graph visualization (optional step)

Run python http server from **graph** folder.

```shell
cd ../graph && python -m SimpleHTTPServer 8000
```

Open browser and go to <http://localhost:8000/index.html> Enjoy!
