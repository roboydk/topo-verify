
import io

import networkx
import networkx as nx
import paramiko
import re
import signal

import time

import sys
import yaml

from functools import wraps
import errno
import os
import signal


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

from topo_graph import BuildNetworkGraph

fname = '../ansible/ansible_hosts'
data_file = 'topo_10_nodes.yaml'
device_w_con_problem = []

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


hosts_w_macs = {}
with open(data_file, 'r') as stream:
    topo_yaml = (yaml.load(stream))


class TopoVerifier:
    def __init__(self):
        with open(fname) as f:
            content = f.readlines()
            content.remove(content[0])
            self.dev_connect = {}
            devices_all = []
            for line in content:
                dev = line.split(' ')
                if len(dev) < 2:
                    pass
                else:

                    dev[1] = dev[1][dev[1].find('=') + 1:]
                    dev[2] = dev[2][dev[2].find('=') + 1:]

                    devices_all.append([dev[1], dev[2], dev[0]])
                    self.dev_connect[dev[0]] = [dev[1], dev[2]]

            devices_online = []
            for dev in devices_all:
                try:
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.WarningPolicy())
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
        graph_nx = BuildNetworkGraph(data_file).build_graph()

        adj = graph_nx.adj
        # print adj
        for node_sender_id in adj:

            for node_receiver_id in adj[node_sender_id]:
                if topo_yaml['nodes'][node_sender_id]['name'] in devices_online:
                    if topo_yaml['nodes'][node_receiver_id]['name'] in devices_online:
                        print 'Checking link {0} ---> {1}'.format(topo_yaml['nodes'][node_sender_id]['name'],
                                                                  topo_yaml['nodes'][node_receiver_id]['name'])
                        self.verify_connection(topo_yaml['nodes'][node_sender_id]['name'],
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
    def verify_connection(self, node_sndr, node_rcvl, counter):

        # Data required to  verify connection
        # On sender side: Interface to Send packet, Destination IP, Source IP, Destination MAC
        # On receiver side: Interface to listen for tcpdump
        # print device_w_con_problem
        # print node_sndr + '  ' + node_rcvl

        try:
            try:
                if [node_sndr, node_rcvl] in device_w_con_problem or [node_rcvl, node_sndr] in device_w_con_problem:
                    sys.exit()
                cl_s = paramiko.SSHClient()
                cl_s.set_missing_host_key_policy(paramiko.WarningPolicy())
                cl_s.connect(self.dev_connect[node_sndr][0], port=int(self.dev_connect[node_sndr][1]),
                             username='vagrant', password='vagrant')

                cl_r = paramiko.SSHClient()
                cl_r.set_missing_host_key_policy(paramiko.WarningPolicy())
                cl_r.connect(self.dev_connect[node_rcvl][0], port=int(self.dev_connect[node_rcvl][1]),
                             username='vagrant', password='vagrant')
            except:
                pass
            for el in hosts_w_macs[node_sndr].keys():
                if el in hosts_w_macs[node_rcvl].keys():
                    link = el

            exec_command_r = 'sudo tcpdump -i {0} -c 10 '.format(hosts_w_macs[node_rcvl][link][0])
            cl_r.exec_command('sudo ifconfig {0} up'.format(hosts_w_macs[node_rcvl][link][0]))
            stdin_r, stdout_r, stderr_r = cl_r.exec_command(exec_command_r)

            stdin_s, stdout_s, stderr_s = \
                cl_s.exec_command('sudo ip addr flush dev {0}'.format(hosts_w_macs[node_sndr][link][0]))
            cl_s.exec_command('sudo ifconfig {0} up'.format(hosts_w_macs[node_sndr][link][0]))

            for k in range(0, 30):
                exec_command_s = 'sudo ./send-raw -i {0} -s {1} -d {2} -m {3}' \
                    .format(hosts_w_macs[node_sndr][link][0], '255.255.255.254', '255.255.255.255',
                            hosts_w_macs[node_rcvl][link][1])
                cl_s.exec_command(exec_command_s)
                k += 1

            # # Debug section
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
                self.verify_connection(node_sndr, node_rcvl, counter)
            else:
                if [node_rcvl, node_sndr] not in device_w_con_problem:
                    device_w_con_problem.append([node_sndr, node_rcvl])
                print "There was 3 tries to establish link. Moving on"
            pass


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
            # var dataset =  { nodes: [
            #     {name: "rtr1"},
            #     {name: "rtr2"}
            # ],
            #     edges: [
            #         {source: 0, target: 1}
            #     ]
            # };
            f.close()


TopoVerifier()



