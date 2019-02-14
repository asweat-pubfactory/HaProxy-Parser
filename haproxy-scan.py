#Purpose of this script is to parse the HaProxyCfg into an ordered format containing node specs for comparing with master record.
#Current implementation requires manual cross referencing

import re
import time
import os.path
import json
from string import digits

allNodes = {}

def getNodes(servers):
	sortedNodes = {}
	for server in servers:
		serverSplit = server.split(' ')

		if serverSplit[1].split(':')[0] not in sortedNodes:
			sortedNodes[serverSplit[1].split(':')[0]] = []

		if serverSplit[0] not in sortedNodes[serverSplit[1].split(':')[0]]:
			sortedNodes[serverSplit[1].split(':')[0]].append(serverSplit[0])

	#total = 0
	#all_nodes = []
	#for key in sortedNodes:
	#	for _node in sortedNodes[key]:
	#		all_nodes.append(_node)
	#
	#	total += sortedNodes[key].__len__()

	#for _test_node in sorted(all_nodes):
	#	print _test_node

	#print total

	return sortedNodes

def getServerEntries(haProxyCfg):
	#Regex for detecting up until port number. E.g "server    pubfactory.net:8443 randomjunkdata"
	p = re.compile('.*:([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])')
	serverEntries = []
	for fileLine in haProxyCfg:
		#if "    server " in fileLine and "#" not in fileLine:
		if "    server " in fileLine and "#" not in fileLine:
			fileLine = fileLine.replace('    server ', '').replace('\n', '')
			serverEntry = p.match(fileLine)
			if serverEntry:
				serverEntries.append(serverEntry.group())
			else:
				print "No Match: " + fileLine


	return sorted(serverEntries)

def checkNodes(nodeFolderLocation, sortedNodes):
	nodes = sorted(sortedNodes.keys())
	#prior = 0
	for node in nodes:
	#	prior += sortedNodes[node].__len__()
		checkNode(nodeFolderLocation, node, sortedNodes[node])
	#print prior

	totalNodes = 0
	for key in sorted(allNodes):
		if allNodes[key].__len__() != 0:
			print key

		for node in allNodes[key]:
			totalNodes += 1
			print "--- " + node[0] + " : " + node[1]

	print "Total Tomcat Instances Configured: " + str(totalNodes)


def pipeHaProxyConfig(proxyCfgFileLocation, nodeFolderLocation):
	with open(proxyCfgFileLocation) as file:
		haProxyCfg = file.readlines()
	
	servers = getServerEntries(haProxyCfg)
	nodes = getNodes(servers)
	checkNodes(nodeFolderLocation, nodes)

def checkNode(nodeFolderLocation, node, subNodes):
	nodeFileUri = nodeFolderLocation + node + ".json"
	if os.path.exists(nodeFileUri) == False:
		#Hotfix - Replace safaribooks.com with pubfactory.net
		node = node.replace('safaribooks.com', 'pubfactory.net')

	nodeFileUri = nodeFolderLocation + node + ".json"

	if os.path.exists(nodeFileUri) == False:
		#Hotfix - Replace safaribooks.com with pubfactory.net
		node = node.replace('pubfactory.net', 'safaribooks.com')

	nodeFileUri = nodeFolderLocation + node + ".json"

	if os.path.exists(nodeFileUri) == False:
		print "NODE FILE MISSING: " + nodeFileUri

	#E.g: AMS-1 
	if node.split('.')[0] not in allNodes.keys():
		allNodes[node.split('.')[0]] = []

	if os.path.exists(nodeFileUri):
		#Node file exists to check attributes

		with open(nodeFileUri) as nodeFile:
			nodeData = json.load(nodeFile)
		
		totalListed = 0
		for subNode in subNodes:
			subNode = subNode.replace('-ams-','-amx-').translate(None, digits)

			try:
				#No instances available for parsing
				if subNode in nodeData['normal']['tomcat']['instances'].keys():
					#Check if instance has ram data
					if 'xmx' in nodeData['normal']['tomcat']['instances'][subNode]:
						allNodes[node.split('.')[0]].append([subNode, nodeData['normal']['tomcat']['instances'][subNode]['xmx']])
					else:
						allNodes[node.split('.')[0]].append([subNode, 'NO RAM DATA'])

					totalListed += 1
			except KeyError as e:
				#Fails for missing tomcat instance array because they're to be ignored for now
				pass

		#if totalListed == 0:
		#	print nodeFileUri
		#	print subNodes

#TODO: Change to params
_proxyCfgFileLocation = "/Users/asweat/Desktop/pf-config/services/haproxy/haproxy-irl-edge/haproxy.cfg"
_nodeFolderLocation = "/Users/asweat/Desktop/pf-chef-config/nodes/"

pipeHaProxyConfig(_proxyCfgFileLocation, _nodeFolderLocation)
