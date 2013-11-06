import requests
import json
import types
import pprint
import logging
from time import sleep
import paramiko
import re
import sys

from collections import namedtuple

IRONIC_API_HOST="10.0.2.15"
CHASSIS_ID="5c785681-2952-4ec3-881b-8cc5e5e39bdf"
LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.DEBUG)
LOGGER.addHandler(logging.StreamHandler(sys.stderr))

def _connect(hostname, username, password, command):
	LOGGER.debug('connecting to %s' % hostname)
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy( paramiko.AutoAddPolicy() )
        try:
                ssh.connect(hostname,
                            username=username,
                            password=password,
                            timeout=30)
        except paramiko.AuthenticationException as ex:
                return 2, "Could not connect: %s" % ex
        except paramiko.BadAuthenticationType as ex:
                return 2, "The remote host doesn't allow password authentication: %s" % ex
        except paramiko.SSHException as ex:
                return 2, "The remote host doesn't allow password authentication: %s" % ex
        except:
                return 2, "Unhandled exception in ssh connection. Check paramaters passed in."
        try:
                stdin, stdout, stderr = ssh.exec_command(command,-1,60)
        except:
                return 2, "Command timedout or terminated unexpectedly"
        try:
                outputBuffer = stdout.read()
        except:
                return 2, "Command output could not be opened."
        ssh.close()
        return 0, outputBuffer

def _exec_seamicrotool(driver_info, command):
    returnCode, commandOutput = _connect(driver_info['address'], driver_info['username'], driver_info['password'], command)
    return commandOutput,returnCode

class RESTBerryPiError(Exception):
	def __init__(self, value):
		self.value = value

	def __str__(self):
		return repr(self.value)

class IronicClient:
	RESPONSE_CODES = {
		200: 'OK',
		202: 'Accepted',
		304: 'Not Modified',
		400: 'Bad Request',
		401: 'Unauthorized',
		403: 'Forbidden',
		404: 'Not Found',
		500: 'Internal Server Error',
		501: 'Internal Server Error (not implemented)'
	}

	def __init__(self, hostname, use_ssl=False, verify_ssl=False):
		self.hostname = hostname
		self.verify_ssl = verify_ssl
		
		if use_ssl:
			self.protocol = "https"
		else:
			self.protocol = "http"

		self.base_uri = "%s://%s" % (self.protocol, self.hostname)

	def send_get(self, location, params):
		url = "/".join([ self.base_uri, location ])
		headers = {'content-type': 'application/json'}

		LOGGER.debug('send_get: url=%s, params=%s, headers=%s' % (url, params, headers))
		r = requests.get(url, verify=self.verify_ssl, params=params)
		#r = requests.get(url, verify=self.verify_ssl, data=json.dumps(params), headers=headers)
		return self.decode_response(r)
	
	def send_post(self, location, params):
		url = "/".join([ self.base_uri, location ])
		headers = {'content-type': 'application/json'}
		
		LOGGER.debug('send_post: url=%s, params=%s, headers=%s' % (url, params, headers))
		r = requests.post(url, verify=self.verify_ssl, params=params, headers=headers)
		#r = requests.post(url, verify=self.verify_ssl, data=json.dumps(params), headers=headers)
		return self.decode_response(r)
	
	def send_post_form(self, location, params):
		url = "/".join([ self.base_uri, location ])
		headers = {'content-type': 'application/json'}
		
		LOGGER.debug('send_post_form: url=%s, params=%s, headers=%s' % (url, params, headers))
		r = requests.post(url, verify=self.verify_ssl, params=params)
		#r = requests.post(url, verify=self.verify_ssl, data=json.dumps(params), headers=headers)
		return self.decode_response(r)
	
	def send_put(self, location, params):
		url = "/".join([ self.base_uri, location ])
		headers = {'content-type': 'application/json'}
		
		r = requests.put(url, verify=self.verify_ssl, params=params)
		#r = requests.put(url, verify=self.verify_ssl, data=json.dumps(params), headers=headers)
		return self.decode_response(r)
	
	def send_patch(self, location, params):
		url = "/".join([ self.base_uri, location ])
		headers = {'content-type': 'application/json'}
		
		#r = requests.patch(url, verify=self.verify_ssl, params=params)
		r = requests.patch(url, verify=self.verify_ssl, data=json.dumps(params), headers=headers)
		return self.decode_response(r)
	
	def send_delete(self, location, params):
		url = "/".join([ self.base_uri, location ])
		headers = {'content-type': 'application/json'}
		
		r = requests.delete(url, verify=self.verify_ssl, params=params)
		#r = requests.delete(url, verify=self.verify_ssl, data=json.dumps(params), headers=headers)
		return self.decode_response(r)
	
	def decode_response(self, response):
		"""
		Handle the response object, and raise exceptions if errors are found.
		"""
		url = response.url
		if response.status_code not in (200, 202, 204, 304):
			http_status_code = response.status_code
			raise RESTBerryPiError('Got HTTP response code %d - %s for %s' % (http_status_code, self.RESPONSE_CODES.get(http_status_code, 'Unknown!'), url))

		if response.status_code in (200,202):
			return json.loads(response.text)
		else:
			return True

	def chassis(self):
		location = "chassis"
		decoded_json_response = self.send_get(location, params={ })

		return decoded_json_response

        def test_temp(self,driver_info):
                
                pool_dict = {}
                cmd = 'enable;show storage pool 6/all brief| exclude (entr\\|---\\|slot\\|Mounted)'
                cmdOutput, err = _exec_seamicrotool(driver_info, cmd)
                flag = 0
                found_a_pool_flag = 0
                pool_for_volume_creation = ""
                for line in cmdOutput.splitlines():
                    if flag == 0:
                       flag = 1
                    else:
                       pool_dict[line.split()[0] + "/" + line.split()[1]] = int(line.split()[3].split(".")[0])
                        
                for names,freesize in pool_dict.items():
                       if (freesize - 30) > 5:
                            pool_for_volume_creation = names
                            found_a_pool_flag = 1
                            break       
                if found_a_pool_flag == 0:
                      print "No more free space on slot"
                """
                Vikrant : We have to come up with a unique volume name scheme uuid function in python
                """
                cmd = 'enable;storage create volume ' + pool_for_volume_creation + '/ironic-volume size 30'
                cmdOutput, err = _exec_seamicrotool(driver_info, cmd)

	def populateNodesFromChassis(self,chassis, driver_info):
		"""
		This method uses server descriptions to determine status of each server
		"ironic available" means node is available for ironic, but not yet in DB
		"ironic unallocated" means in ironic db, not allocated
		"ironic allocated" means in ironic db, allocated for use
		This method looks for all servers in "ironic available" mode and puts them in DB
		Todo: nodeInfo offsets may not work on non-opteron chassis, need to test
		"""
		nodeList = []
		cmd = 'enable;show server description | i /'
		cmdOutput, err = _exec_seamicrotool(driver_info, cmd)
		for line in cmdOutput.splitlines():
			LOGGER.debug(line)
			parsedLine = line.split()
			if len(parsedLine) > 1 and parsedLine[1] == "ironic" and parsedLine[2] == "available":
				nodeList.append(parsedLine[0])
		
		cmdOutput, err = _exec_seamicrotool(driver_info, "show running-config hostname")
		hostname = cmdOutput.split()[1]
		
		properties = { "type":"node", "disk":0 }
		for node in nodeList:
			nodeProperties = properties
			nodeProperties['id'] = "%s Card %s" % (hostname,node)
			cmd = "enable;show server summary %s | include DDR" % (node)
			LOGGER.debug(cmd)
			cmdOutput, err = _exec_seamicrotool(driver_info, cmd)
			LOGGER.debug(cmdOutput)
			nodeInfo = cmdOutput.split()

			if nodeInfo[6] == "Opteron":
				nodeProperties['arch'] = "x86_64"
				nodeProperties['cpus'] = 8
				ramOffset = 9
			elif nodeInfo[6] == "Xeon":
				nodeProperties['arch'] = "x86_64"
				nodeProperties['cpus'] = 4
				#not sure if below is correct, need to test
				ramOffset = 9
			
			match = re.search(r'w/(?P<ram>\d+)GB', cmdOutput, re.M|re.I)
			if match:
				ram = int(match.group('ram'))
				nodeProperties['ram'] = ram*1024
			
			driver_info['ccard'] = node
			newNode = self.addNode(chassis=chassis,driver="pxe_seamicro", properties=nodeProperties,driver_info=driver_info)
			
			cmd = 'enable;config t;server id %s;description "ironic unallocated"' % (node)
			cmdOutput, err = _exec_seamicrotool(driver_info, cmd)
		return True
	
	def clearServerState(self, driver_info):
		cmd = 'enable;config t;storage assign-clear %s all' % (driver_info['ccard'])
		cmdOutput, err = _exec_seamicrotool(driver_info, cmd)
		
		basecmd = "enable;conf t;server id " + driver_info['ccard'] + ";nic 0;"
		cmd1 = "show configuration | include untagged-vlan"
		out, err = _exec_seamicrotool(driver_info, basecmd + cmd1)
		out, err = _exec_seamicrotool(driver_info, basecmd + "no " + out)
		
		cmd = 'enable;config t;server id %s;description "ironic available"' % (driver_info['ccard'])
		cmdOutput, err = _exec_seamicrotool(driver_info, cmd)
	

        def nodesDetail(self):
                location = "nodes/detail"
                decoded_json_response = self.send_get(location, params={ })

                return decoded_json_response


	def nodes(self):
		location = "nodes"
		decoded_json_response = self.send_get(location, params={ })

		return decoded_json_response

	
	def getNode(self,uuid):
		location = "nodes/%s" % (uuid)
		decoded_json_response = self.send_get(location, params={ })

		return decoded_json_response

	
	def addNode(self,chassis="",driver="",properties={},driver_info={}):
		location = "nodes"
		params = {"chassis" : chassis, "driver" : driver, "properties" : properties, "driver_info" : driver_info}
		decoded_json_response = self.send_post(location, params=params)
		return decoded_json_response

	
	def clearAllNodes(self):
		for node in self.nodes()['nodes']:
			self.clearServerState(self.getNode(node['uuid'])['driver_info'])
			self.deleteNode(node['uuid'])
			#sleep or we overload the chassis cli
			sleep(2)
		return True
	

	def updateNode(self, uuid, params=[]):
		location = "nodes/%s" % (uuid)

		decoded_json_response = self.send_patch(location, params=params)
		return decoded_json_response

	
	def deleteNode(self,uuid):
		location = "nodes/%s" % (uuid)
		decoded_json_response = self.send_delete(location, params={ })

		return decoded_json_response
	
	def addNode(self,chassis,driver,properties="",driver_info=""):
		location = "nodes"
		params = {"chassis" : chassis, "driver" : driver, "properties" : properties, "driver_info" : driver_info}
		decoded_json_response = self.send_post(location, params=params)
		return decoded_json_response
	
	def getNodePower(self, uuid):
		location = "nodes/%s/state/power" % (uuid)
		decoded_json_response = self.send_get(location, params="")
		return decoded_json_response
	
	def setNodePower(self, uuid, powerOn):
		location = "nodes/%s/state/power" % (uuid)
		if powerOn:
			params = { 'target': 'power on' }
		else:
			params = { 'target': 'power off' }
		decoded_json_response = self.send_put(location, params=params)
		return decoded_json_response
	
	def setNodeDisk(self, uuid, diskSize):
		location = "nodes/%s/vendor_passthru/set_disk_size" % (uuid)
		params = {"size":diskSize}
		decoded_json_response = self.send_post(location, params=params)
		return decoded_json_response


	def setNodeVlan(self, uuid, vlan_id):
		location = "nodes/%s/vendor_passthru/set_vlan" % (uuid)
		params = {"vlan":vlan_id}
		decoded_json_response = self.send_post(location, params=params)
		return decoded_json_response

	
	def assignVlanToAllNodes(self,vlan_id):
		for node in self.nodes()['nodes']:
			self.setNodeVlan(node['uuid'],vlan_id)
			#sleep or we overload the chassis cli
			sleep(2)
		return True

	
	def powerAllNodes(self,powerOn):
		for node in self.nodes()['nodes']:
			self.setNodePower(node['uuid'],powerOn)
		return True

	
def testNodeCreateDelete(ironic):
	driver_info = { 'username': 'admin', 'password': 'seamicro', 'ccard': u'57/0','address': '10.216.142.87' }
	properties = { 'id': "CH877 Card57/0", "type":"node", "arch":"x86_64", "cpus": 8, "disk":0, "ram":32768 }
	
	newNode = ironic.addNode(chassis="c2090023-8d6b-4cce-b4f3-6cef94fccc99",driver="pxe_seamicro", properties=properties,driver_info=driver_info)
	
	pprint.pprint(newNode)
	newNodeUUID = newNode['uuid']

	ironic.deleteNode(uuid=newNodeUUID)

def testNodeCreatePATCHDelete(ironic):
	driver_info = { 'username': 'admin', 'password': 'seamicro', 'ccard': u'57/0','address': '10.216.142.87' }
	properties = { 'id': "CH877 Card57/0", "type":"node", "arch":"x86_64", "cpus": 8, "disk":0, "ram":32768 }
	
	newNode = ironic.addNode(chassis="c2090023-8d6b-4cce-b4f3-6cef94fccc99",driver="pxe_seamicro", properties=properties,driver_info={})
	
	pprint.pprint(newNode)
	newNodeUUID = newNode['uuid']
	
	params = [
		{"path": "/driver_info/address", "value": "10.216.142.87", "op": "add"},
		{"path": "/driver_info/username", "value": "admin", "op": "add"},
		{"path": "/driver_info/password", "value": "seamicro", "op": "add"},
		{"path": "/driver_info/ccard", "value": "57/0", "op": "add"}
		]	
	
	ironic.updateNode(uuid=newNodeUUID,params=params)
	
	pprint.pprint(ironic.getNode(uuid=newNodeUUID))
	ironic.deleteNode(uuid=newNodeUUID)

def testNodeCreateSetDiskVLANDelete(ironic):
	driver_info = { 'username': 'admin', 'password': 'seamicro', 'ccard': u'57/0','address': '10.216.142.87' }
	properties = { 'id': "CH877 Card57/0", "type":"node", "arch":"x86_64", "cpus": 8, "disk":0, "ram":32768 }
	print "###Creating Node###"
	newNode = ironic.addNode(chassis="c2090023-8d6b-4cce-b4f3-6cef94fccc99",driver="pxe_seamicro", properties=properties,driver_info=driver_info)
	pprint.pprint(newNode)
	newNodeUUID = newNode['uuid']
	print "###Setting Disk###"
	ironic.setNodeDisk(newNodeUUID,30)
	sleep(3)
	pprint.pprint(ironic.getNode(newNodeUUID))
	print "###Setting VLAN###"
	ironic.setNodeVlan(newNodeUUID,4)
	sleep(3)
	pprint.pprint(ironic.getNode(newNodeUUID))
	
	ironic.deleteNode(uuid=newNodeUUID)

def server_discover(chassis_id):
	ironic = IronicClient(hostname="%s:6385/v1" % IRONIC_API_HOST, use_ssl=False, verify_ssl=False) 
	return ironic.populateNodesFromChassis(chassis=CHASSIS_ID, driver_info={ 'username': 'admin', 'password': 'seamicro', 'address': '10.216.142.87' })

def server_provision(request, instance_id):
	LOGGER.debug('provision: id=%s' % instance_id)
	LOGGER.debug('provision: request=%s' % request)

def server_assign_disk(instance_id, volume_size):
	ironic = IronicClient(hostname="%s:6385/v1" % IRONIC_API_HOST, use_ssl=False, verify_ssl=False)
	return ironic.setNodeDisk(instance_id, volume_size)

def server_assign_vlan(instance_id, vlan_id, nic=0):
	ironic = IronicClient(hostname="%s:6385/v1" % IRONIC_API_HOST, use_ssl=False, verify_ssl=False) 
	return ironic.setNodeVlan(instance_id, vlan_id, nic)

def server_power_state(instance_id):
	ironic = IronicClient(hostname="%s:6385/v1" % IRONIC_API_HOST, use_ssl=False, verify_ssl=False) 
	return ironic.getNodePower(instance_id)


def server_reboot(request, instance_id, soft_reboot=False):
	server_stop(request, instance_id)
	server_start(request, instance_id)


def server_stop(request, instance_id):
	ironic = IronicClient(hostname="%s:6385/v1" % IRONIC_API_HOST, use_ssl=False, verify_ssl=False)
	ironic.setNodePower(instance_id, False)


def server_start(request, instance_id):
	ironic = IronicClient(hostname="%s:6385/v1" % IRONIC_API_HOST, use_ssl=False, verify_ssl=False)
	return ironic.setNodePower(instance_id, True)

def server_get(request, instance_id):
	ironic = IronicClient(hostname="%s:6385/v1" % IRONIC_API_HOST, use_ssl=False, verify_ssl=False)
	node = ironic.getNode(instance_id)
	node.update({ u'id': node['uuid'], u'name': node['properties']['id'] })
	node_obj = namedtuple('Node', node.keys())
	return node_obj(**node)

def nodes(request, search_opts=None):
	ironic = IronicClient(hostname="%s:6385/v1" % IRONIC_API_HOST, use_ssl=False, verify_ssl=False)
	discovered_nodes = ironic.nodesDetail()
	named_tuples = []
	for node in discovered_nodes['nodes']:
		node.update({ u'id': node['uuid'], u'name': node['properties']['id'] })
		node_obj = namedtuple('Node', node.keys())
		#file('/tmp/objs','a').write(str(node))
		named_tuples.append(node_obj(**node))
	print [ nt.name for nt in named_tuples ]
	return named_tuples, None

def main():
	ironic = IronicClient(hostname="%s:6385/v1" % IRONIC_API_HOST, use_ssl=False, verify_ssl=False)
	
	### INDIVIDUAL NODE TESTS
	#testNodeCreateDelete(ironic)
	#testNodeCreatePATCHDelete(ironic)
	#testNodeCreateSetDiskVLANDelete(ironic)
	#ironic.setNodePower("db811f96-980f-4acb-ba7c-95a391413d9b",False)
	
	
	### GROUP NODE TESTS, WILL EXECUTE ON ALL NODES IN IRONIC DB
	
	#ironic.populateNodesFromChassis(chassis=CHASSIS_ID, driver_info={ 'username': 'admin', 'password': 'seamicro', 'address': '10.216.142.87' })
	ironic.populateNodesFromChassis(chassis=CHASSIS_ID, driver_info={ 'username': 'admin', 'password': 'seamicro', 'address': '192.168.142.10' })
	#pprint.pprint(ironic.getNodePower('9ec8a89a-b319-4f5d-8c5e-c73c618a0d34'))

	pprint.pprint(ironic.nodesDetail())
	#ironic.assignVlanToAllNodes(3)
	
	#ironic.powerAllNodes(True)
	
	#ironic.powerAllNodes(False)
	#ironic.clearAllNodes()
	
	
	
if __name__ == '__main__':
	main()
