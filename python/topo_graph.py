import sys
import yaml
import networkx as nx


class BuildNetworkGraph:

    def __init__(self, data_file):
        self.data_file = data_file
        self.open_file()

    def open_file(self):
        with open(self.data_file, 'r') as stream:
            try:
                self.topo_yaml = (yaml.load(stream))
            except yaml.YAMLError as exc:
                print(exc)
                sys.exit('YAML file not available')

    def build_graph(self):
        graph = nx.Graph()
        edges = {}
        for i in range(0, len(self.topo_yaml['nodes'])):
            graph.add_node(i, node_data=self.topo_yaml['nodes'][i])

        for i in range(0, len(self.topo_yaml['nodes'])):
            for wire in self.topo_yaml['nodes'][i]['interfaces']:
                if wire['link-name'] in edges.keys():
                    edges[wire['link-name']].append(i)
                else:
                    edges[wire['link-name']] = [i]

        for link in edges:
            if len(edges[link]) == 2:
                # print 'Adding edge: {0}  {1} {2}'.format(link, edges[link][0], edges[link][1])
                graph.add_edge(edges[link][0], edges[link][1])
            else:
                print 'Probably {0} opened only from one side'.format(link)
        return graph


