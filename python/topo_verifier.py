import io
import re
import time
import sys
import yaml

from functools import wraps
import errno
import os
import signal
from topo_graph import BuildNetworkGraph
from netmiko import ConnectHandler
from paramiko import SSHClient, AutoAddPolicy
from scp import SCPClient
"""
2 source file for verifier:

topology in YAML format,
ansible_hosts - autocreated in case of vagrant orchestratration, manually(for now in VIRL)

virl@virl:~/Documents/projects/topo-verify/ansible$
ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook playbooks/eline.yml -i ansible_hosts --extra-vars "username=cisco"

~/Documents/projects/topo-verify/python
python topo_verifier.py ../ansible/ansible_hosts topo_5_nodes_virl.yaml
"""


class TimeoutError(Exception):
    pass


def handler_function():
    sys.exit()


def timeout(seconds=10, error_message=os.strerror(errno.ETIME)):
    def decorator(func):
        def _handle_timeout(signum, frame):
            raise TimeoutError(error_message)

        def wrapper(*args, **kwargs):
            signal.signal(signal.SIGALRM, _handle_timeout)
            signal.alarm(seconds)
            try:
                result = func(*args, **kwargs)
            finally:
                signal.alarm(0)
            return result

        return wraps(func)(wrapper)

    return decorator


def find_connected_link(node1, node2):
    l1_all = []
    l2_all = []
    for l1 in node1['interfaces']:
        l1_all.append(l1['link-name'])
    for l2 in node2['interfaces']:
        l2_all.append(l2['link-name'])
    for elem in l1_all:
        if elem in l2_all:
            return elem
        else:
            pass


hosts_file = sys.argv[1]
data_file = sys.argv[2]
device_w_con_problem = []
devices_online = []
hosts_w_macs = {}
with open(data_file, 'r') as stream:
    topo_yaml = (yaml.load(stream))


def find(lst, key, value):
    # Help function to find index of dict nested in list
    for i, dic in enumerate(lst):
        if dic[key] == value:
            return i
    return -1


with open(hosts_file) as f:
    content = f.readlines()
    content.remove(content[0])
    dev_connect = {}
    devices_all = []
    for line in content:
        dev = line.split(' ')
        if len(dev) < 2:
            pass
        else:
            dev[1] = dev[1][dev[1].find('=') + 1:]
            dev[2] = dev[2][dev[2].find('=') + 1:]
            devices_all.append([dev[1], dev[2], dev[0]])
            dev_connect[dev[0]] = [dev[1], dev[2]]
        f.close()


class TopoVerifier:
    graph_nx = BuildNetworkGraph(data_file).build_graph()
    # piece of code to replace id to device name in adjacement graph
    id_name = {}
    for i in range(0, len(topo_yaml['nodes'])):
        id_name[i] = topo_yaml['nodes'][i]['name']
    adj_with_names = {}
    for id in graph_nx.adj:

        adj_with_names[topo_yaml['nodes'][id]['name']] = []
        for key in graph_nx.adj[id].keys():
            adj_with_names[topo_yaml['nodes'][id]['name']].append(id_name[key])

    def __init__(self):

        # print graph_nx.adj
        print devices_all
        # print find(topo_yaml['nodes'], 'name', 'iosxrv9000-1')

        # Options to select here:
        # Raw packet injection
        # Python injection
        # LLDP
        # UDP
        # self.lldp_verify()
        # self.verify_connection_udp()
        # self.virl_topo_verify()

        self.vagrant_topo_verify()

    def lldp_verify(self):
        print 'Start checking LLDP connections'
        lldp_connections = {}
        gr_adj = BuildNetworkGraph(data_file).build_graph().adj

        for device in devices_all:
            dev_name, dev_ip, dev_port = device[2], device[0], int(device[1])
            # print dev_name
            dev_index = find(topo_yaml['nodes'], 'name', dev_name)
            if topo_yaml['nodes'][dev_index]['os'] == 'linux_ubuntu':
                print 'ubuntu configuration'
                ssh = SSHClient()
                ssh.load_system_host_keys()
                ssh.set_missing_host_key_policy(AutoAddPolicy())
                ssh.connect(dev_ip, port=dev_port, username='cisco', password='cisco')

                # SCPCLient takes a paramiko transport as its only argument
                scp = SCPClient(ssh.get_transport())
                scp.put('../scripts/lldp/lldp_script.sh')
                scp.put('../scripts/lldp/libconfig9_1.4.9-2_amd64.deb')
                scp.put('../scripts/lldp/libnl1_1.1-8ubuntu1_amd64.deb')
                scp.put('../scripts/lldp/lldpad_0.9.46-2_amd64.deb')
                # ssh.exec_command('sudo -i')
                ssh.exec_command('chmod 755 lldp_script.sh')
                si, so, se = ssh.exec_command('dpkg -i libconfig9_1.4.9-2_amd64.deb ')
                print se.read()
                ssh.exec_command('dpkg -i libnl1_1.1-8ubuntu1_amd64.deb ')
                ssh.exec_command('dpkg -i lldpad_0.9.46-2_amd64.deb')
                ssh.exec_command('lldpad -d')
                ssh.exec_command('./lldp_script.sh')

                # sin, sout,serr =  ssh.exec_command('s && whoami')
                # print sout.read()
            #      sudo lldptool -t  -n -i eth1
            elif topo_yaml['nodes'][dev_index]['os'] == 'cisco_iosxr':

                cisco_ios_xrv = {
                    'device_type': 'cisco_xr',
                    'ip': dev_ip,
                    'username': 'cisco',
                    'password': 'cisco',
                    'port': dev_port,
                    'secret': 'secret',
                    'verbose': False,
                }

                net_connect = ConnectHandler(**cisco_ios_xrv)
                output = net_connect.send_config_set(['lldp', 'commit', 'end'])

                # print(output)

                output = net_connect.send_command('show lldp neighbors')
                # print(output.split('\n'))
                outp_lldp = output.split('\n')[7:-3]
                print outp_lldp
                print len(outp_lldp)





                # for key in gr_adj.keys():
                #     print '{0} is connected to {1}'.format(key, gr_adj[key])

    def virl_topo_verify(self):

        cmd_pre = 'cd /home/cisco/scripts/ && sudo python xr_log_grubber.py pre'
        cmd_after = 'cd /home/cisco/scripts/ && sudo python xr_log_grubber.py after'
        r = SSHClient()
        r.set_missing_host_key_policy(AutoAddPolicy())
        r.connect('172.16.1.116', port=57722, username='test', password='test')
        # s.connect('172.16.1.117', port=57722, username='test', password='test',look_for_keys=False, allow_agent=False)
        s = SSHClient()
        s.set_missing_host_key_policy(AutoAddPolicy())
        s.connect('172.16.1.117', port=57722, username='test', password='test')

        stdin, stdout, stderr = r.exec_command(cmd_pre)
        print stdout.read()
        print stderr.read()
        # time.sleep(5)
        i = 0
        for i in range(0, 3):
            i += 1
            send_in, send_out, send_err=  s.exec_command('cd /home/cisco/scripts && sudo ./send-raw -d 255.255.255.254 -s 10.0.0.18 -i Gi0_0_0_0 -m fa:16:3e:00:c1:60')
            # print send_out.read()
            # print send_err.read()
        # print send_out.read()
        stdin, stdout, stderr = r.exec_command(cmd_after)
        print 'done'
        k = stdout.read()
        print stderr.read()
        # print stderr.read()
        # print k
        if 'dst: 255.255.255.254' in k:
            print 'yahoo'

        # fine_links = []
        #
        # for k, v in self.adj_with_names.iteritems():
        #     """
        #     Every node can be connected to few nodes.
        #     So we need to verify nested loop over here. v - ['server1', 'server2']
        #     """
        #     for l in v:
        #         receiver_id = find(topo_yaml['nodes'], 'name', l)
        #         receiver = topo_yaml['nodes'][receiver_id]
        #         sender_id = find(topo_yaml['nodes'], 'name', k)
        #         sender = topo_yaml['nodes'][sender_id]
        #         link_num = find_connected_link(receiver, sender)
        #         # print receiver['interfaces']
        #         print receiver
        #         receiver_dev = find(receiver['interfaces'], 'link-name', link_num)
        #         # print receiver_dev
        #         receiver_interface = topo_yaml['nodes'][receiver_id]['interfaces'][0]['interface']
        #
        #         # print dev_connect[l]
        #         # print 'connected_link {0}'.format(link_num)
        #         if
        #         packet_receiver = SSHClient()
        #         packet_receiver.set_missing_host_key_policy(AutoAddPolicy())
        #         packet_receiver.connect(dev_connect[l][0], port=int(dev_connect[l][1]),
        #                            username=cred_r, password=cred_r)
        #
        #         input_command = 'ifconfig {0}'.format(receiver_interface). \
        #             replace('GigabitEthernet', 'Gi').replace('/', '_')
        #         s_in, s_out, s_err = packet_receiver.exec_command(input_command)
        #         # print 'input ' + input_command
        #
        #         # print s_out.read()
        #         receiver_ip = re.search(r'inet addr:(\S+)', s_out.read()).group(1)
        #
        #         # print "\n*** DEBug Message\n" \
        #         #       "dev sender {0} connection {1} \n" \
        #         #       "dev receiver {2} connection {3}  \n" \
        #         #       "connected link {4}\n" \
        #         #       "Receiver interface - {5}  IP - {6}\n" \
        #         #       "***".format(sender['name'], dev_connect[k],
        #         #                    receiver['name'], dev_connect[l],
        #         #                    link_num, receiver_interface, receiver_ip)
        #
        #         r_in, r_out, r_err = packet_receiver.exec_command('python ~/scripts/sock_receiver.py ' + receiver_ip)
        #
        #         packet_sender = SSHClient()
        #         packet_sender.set_missing_host_key_policy(AutoAddPolicy())
        #         packet_sender.connect(dev_connect[k][0], port=int(dev_connect[k][1]),
        #                            username=cred_s, password=cred_s)
        #         s_in, s_out, s_err = packet_sender.exec_command('python ~/scripts/sock_sender.py ' + receiver_ip)
        #         if 'Checking connectivity' in r_out.read():
        #             fine_links.append(sender['name'] + ' ' + receiver['name'])
        #             # print s_out.read()
        # print 'UDP Connection verified for following links:'
        # for f_l in fine_links:
        #     print f_l + u' \u2713'.encode('utf8')

    def vagrant_topo_verify(self):
        for dev in devices_all:
            try:
                client = SSHClient()
                client.set_missing_host_key_policy(AutoAddPolicy())
                client.connect(dev[0], port=int(dev[1]), username='vagrant', password='vagrant')
                devices_online.append(dev[2])
                # stdin, stdout, stderr = client.exec_command("ifconfig -a | grep 'HWaddr\|inet addr'")
                stdin, stdout, stderr = client.exec_command("ifconfig -a | grep 'HWaddr'")

                # print stdout.read().replace('inet addr:127.0.0.1  Mask:255.0.0.0', '')
                ind = next(index for (index, d) in enumerate(topo_yaml['nodes']) if d["name"] == dev[2])
                outp = []
                outp = stdout.read().replace('Link', '').replace('HWaddr', '').replace('encap:Ethernet', '').split()
                l_name_dict = {}

                if 'eth0' in outp:
                    del outp[outp.index('eth0'): outp.index('eth0') + 2]
                if 'fwd_ew' in outp:
                    del outp[outp.index('fwd_ew'): outp.index('fwd_ew') + 2]
                if 'Mg0_RP0_CPU0_0' in outp:
                    del outp[outp.index('Mg0_RP0_CPU0_0'): outp.index('Mg0_RP0_CPU0_0') + 2]
                if 'fwdintf' in outp:
                    del outp[outp.index('fwdintf'): outp.index('fwdintf') + 2]
                print outp
                for i in range(0, len(outp) / 2):
                    l_name_dict[topo_yaml['nodes'][ind]['interfaces'][i]['link-name']] = [outp[i * 2],
                                                                                          outp[i * 2 + 1]]

                hosts_w_macs[dev[2]] = l_name_dict
                print hosts_w_macs
                client.close()

            except Exception, e:
                print str(e)

        adj = self.graph_nx.adj
        # print adj
        for node_sender_id in adj:

            for node_receiver_id in adj[node_sender_id]:
                if topo_yaml['nodes'][node_sender_id]['name'] in devices_online:
                    if topo_yaml['nodes'][node_receiver_id]['name'] in devices_online:
                        print 'Checking link {0} ---> {1}'.format(topo_yaml['nodes'][node_sender_id]['name'],
                                                                  topo_yaml['nodes'][node_receiver_id]['name'])
                        self.verify_connection_raw(topo_yaml['nodes'][node_sender_id]['name'],
                                                   topo_yaml['nodes'][node_receiver_id]['name'], 0)
                        time.sleep(0.1)
        # print dev
        print "Online and reachable devices {0}".format(devices_online)
        # print devices_all
        # print self.dev_connect
        if len(device_w_con_problem) == 0:
            print "All links established!"
        else:
            print "Device with connection problems in between: {0}".format(device_w_con_problem)
        self.prepare_data_for_graph()

    @timeout(3, "Something went wrong")
    def verify_connection_raw(self, node_sndr, node_rcvl, counter):

        # Data required to  verify connection
        # On sender side: Interface to Send packet, Destination IP, Source IP, Destination MAC
        # On receiver side: Interface to listen for tcpdump
        # print device_w_con_problem
        # print node_sndr + '  ' + node_rcvl
        try:
            try:
                if [node_sndr, node_rcvl] in device_w_con_problem or [node_rcvl, node_sndr] in device_w_con_problem:
                    sys.exit()
                cl_s = SSHClient()
                cl_s.set_missing_host_key_policy(AutoAddPolicy())
                cl_s.connect(dev_connect[node_sndr][0], port=int(dev_connect[node_sndr][1]),
                             username='vagrant', password='vagrant')

                cl_r = SSHClient()
                cl_r.set_missing_host_key_policy(AutoAddPolicy())
                cl_r.connect(dev_connect[node_rcvl][0], port=int(dev_connect[node_rcvl][1]),
                             username='vagrant', password='vagrant')
                # print 'dev sender: {0}, dev receiver {1}'.format(dev_connect[node_sndr][1], dev_connect[node_rcvl][1])
            except:
                pass
            for el in hosts_w_macs[node_sndr].keys():
                if el in hosts_w_macs[node_rcvl].keys():
                    link = el

            exec_command_r = 'sudo tcpdump -i {0} -c 10 '.format(hosts_w_macs[node_rcvl][link][0])
            cl_r.exec_command('sudo ifconfig {0} up'.format(hosts_w_macs[node_rcvl][link][0]))
            # print 'node is {0}, receive command is {1}'.format(hosts_w_macs[node_rcvl], exec_command_r)

            stdin_r, stdout_r, stderr_r = cl_r.exec_command(exec_command_r)

            stdin_s, stdout_s, stderr_s = \
                cl_s.exec_command('sudo ip addr flush dev {0}'.format(hosts_w_macs[node_sndr][link][0]))
            cl_s.exec_command('sudo ifconfig {0} up'.format(hosts_w_macs[node_sndr][link][0]))
            cl_s.exec_command('sudo chmod 755 scripts/send-raw')

            exec_command_s = 'sudo ./scripts/send-raw -i {0} -s {1} -d {2} -m {3}' \
                .format(hosts_w_macs[node_sndr][link][0], '255.255.255.254', '255.255.255.255',
                        hosts_w_macs[node_rcvl][link][1])

            # print 'node is {0}, send command is \n {1}'.format(hosts_w_macs[node_sndr], exec_command_s)

            for k in range(0, 30):

                cl_s.exec_command(exec_command_s)
                k += 1

            # Debug section
            # print 'Link between devices is ' + link
            # print 'sudo ifconfig {0} up'.format(hosts_w_macs[node_sndr][link][0])
            # print 'sudo ip addr flush dev {0}'.format(hosts_w_macs[node_sndr][link][0])
            # print exec_command_s
            # print exec_command_r

            if len([m.start() for m in
                    re.finditer('IP 255.255.255.254 > 255.255.255.255: ICMP echo request', stdout_r.read())]) >= 5:
                print '   Link  {0} --->  {1} '.format(node_sndr, node_rcvl) + u'\u2713'.encode('utf8')
                # print 'Link  {0} --->  {1} established'.format(node_sndr, node_rcvl)
            else:
                print 'Sorry, there is some problem'
                device_w_con_problem.append([node_sndr, node_rcvl])

            cl_s.close()
            cl_r.close()
        except:
            # print '{0} try'.format(counter)
            counter += 1
            if counter < 5:
                self.verify_connection_raw(node_sndr, node_rcvl, counter)
            else:
                if [node_rcvl, node_sndr] not in device_w_con_problem:
                    device_w_con_problem.append([node_sndr, node_rcvl])
                print "There was 3 tries to establish link. Moving on"
            pass

    def verify_connection_udp(self):
        fine_links = []
        # print 'dev con'
        # print dev_connect
        # Netmask:   255.255.255.252 = 30
        # Network:   10.0.0.220/30
        # Broadcast: 10.0.0.223
        # HostMin:   10.0.0.221
        # HostMax:   10.0.0.222
        # Hosts/Net: 2
        # print self.graph_nx.adj


        for k, v in self.adj_with_names.iteritems():
            """
            Every node can be connected to few nodes.
            So we need to verify nested loop over here. v - ['server1', 'server2']
            """
            # print k, v
            for l in v:
                receiver_id = find(topo_yaml['nodes'], 'name', l)
                receiver = topo_yaml['nodes'][receiver_id]
                sender_id = find(topo_yaml['nodes'], 'name', k)
                sender = topo_yaml['nodes'][sender_id]
                link_num = find_connected_link(receiver, sender)
                # print receiver['interfaces']
                # print link_num
                receiver_dev = find(receiver['interfaces'], 'link-name', link_num)
                # print receiver_dev
                receiver_interface = topo_yaml['nodes'][receiver_id]['interfaces'][0]['interface']

                # print dev_connect[l]
                # print 'connected_link {0}'.format(link_num)

                udp_receiv = SSHClient()
                udp_receiv.set_missing_host_key_policy(AutoAddPolicy())
                udp_receiv.connect(dev_connect[l][0], port=int(dev_connect[l][1]),
                                   username='cisco', password='cisco')

                input_command = 'ifconfig {0}'.format(receiver_interface). \
                    replace('GigabitEthernet', 'Gi').replace('/', '_')
                s_in, s_out, s_err = udp_receiv.exec_command(input_command)
                # print 'input ' + input_command

                # print s_out.read()
                receiver_ip = re.search(r'inet addr:(\S+)', s_out.read()).group(1)

                # print "\n*** DEBug Message\n" \
                #       "dev sender {0} connection {1} \n" \
                #       "dev receiver {2} connection {3}  \n" \
                #       "connected link {4}\n" \
                #       "Receiver interface - {5}  IP - {6}\n" \
                #       "***".format(sender['name'], dev_connect[k],
                #                    receiver['name'], dev_connect[l],
                #                    link_num, receiver_interface, receiver_ip)

                r_in, r_out, r_err = udp_receiv.exec_command('python ~/scripts/sock_receiver.py ' + receiver_ip)

                udp_sender = SSHClient()
                udp_sender.set_missing_host_key_policy(AutoAddPolicy())
                udp_sender.connect(dev_connect[k][0], port=int(dev_connect[k][1]),
                                   username='cisco', password='cisco')
                s_in, s_out, s_err = udp_sender.exec_command('python ~/scripts/sock_sender.py ' + receiver_ip)
                if 'Checking connectivity' in r_out.read():
                    fine_links.append(sender['name'] + ' ' + receiver['name'])
                    # print s_out.read()
        print 'UDP Connection verified for following links:'
        for f_l in fine_links:
            print f_l + u' \u2713'.encode('utf8')

    @staticmethod
    def prepare_data_for_graph():
        G = BuildNetworkGraph(data_file).build_graph()
        adj = G.adj
        file_name = "../graph/ds.js"
        mode = 'w'

        with io.FileIO(file_name, mode) as f:
            # print G.nodes(data=True)
            nodes_str = ''
            for node in G.nodes(data=True):
                # print node[1]['node_data']['name']
                nodes_str += '{name: "' + node[1]['node_data']['name'] + '"}, '

            f.write('var dataset = { nodes: [  ' + nodes_str[:-2])

            edges = []
            for k in adj:
                for v in adj[k]:
                    # print '{0} pings {1}'.format(k, v)
                    if k < v:
                        edges.append([k, v])
            edges_str = ''
            for e in edges:
                ind1 = next(index for (index, d) in enumerate(topo_yaml['nodes'])
                            if d["name"] == G.nodes(data=True)[e[0]][1]['node_data']['name'])
                ind2 = next(index for (index, d) in enumerate(topo_yaml['nodes'])
                            if d["name"] == G.nodes(data=True)[e[1]][1]['node_data']['name'])
                link = find_connected_link(topo_yaml['nodes'][ind1],
                                           topo_yaml['nodes'][ind2])
                edges_str += '{source: ' + str(e[0]) + ' , target: ' + str(e[1]) + ', link: "' + link + '" }, '

            f.write(' ], edges: [ ')
            f.write(edges_str[:-2])
            f.write(" ]};")
            f.close()


TopoVerifier()
