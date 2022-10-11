from datetime import datetime

# Prisma Access
from .serviceSetup import *
from .policyObjects import *

class prismaAccess:
	"""
	Prisma Access class that is used for getting/making changes to Prisma Access Cloud Managed.
	"""
	def checkTokenStillValid(self):
		"""
		Checks to see if the token is still valid. 
		Returns true is still in 15minute window. 
		Returns false if not.
		"""
		rightNow = datetime.now()
		tokenValid = bool(rightNow < self.saseToken['expiresOn'])
		return tokenValid

	def paAddressesListAddresses(self, __folder="Shared"):
		if self.checkTokenStillValid():
			paAddresses = addresses.addresses(self.saseApi, self.saseToken, self.contentType, self.saseAuthHeaders)
			paAddresses.paAddressesListAddresses(__folder)
		else:
			print("Please request new token and create new prismaAccess object.")

	def paAddressesCreate(self, __addressObject, __folder="Shared"):
		if self.checkTokenStillValid():
			paAddresses = addresses.addresses(self.saseApi, self.saseToken, self.contentType, self.saseAuthHeaders)
			paAddresses.paAddressesCreate(__addressObject, __folder)
		else:
			print("Please request new token and create new prismaAccess object.")

	def paTagsListTags(self, __folder="Shared"):
		if self.checkTokenStillValid():
			paTag = tags.tags(self.saseApi, self.saseToken, self.contentType, self.saseAuthHeaders)
			paTag.paTagsListTags(__folder)
		else:
			print("Please request new token and create new prismaAccess object.")

	def paTagCreate(self, __tagObject, __folder="Shared"):
		if self.checkTokenStillValid():
			paTag = tags.tags(self.saseApi, self.saseToken, self.contentType, self.saseAuthHeaders)
			paTag.paTagCreate(__tagObject, __folder)
		else:
			print("Please request new token and create new prismaAccess object.")

	def paLicenseTypesListTypes(self):
		if self.checkTokenStillValid():
			paLicenses = licenseTypes.licenseTypes(self.saseApi, self.saseToken, self.contentType, self.saseAuthHeaders)
			paLicenses.paLicenseTypesListTypes()
		else:
			print("Please request new token and create new prismaAccess object.")

	def paLocationsListLocations(self):
		"""List all the Prisma Access Locations"""
		if self.checkTokenStillValid():
			paLocations = listLocations.listLocations(self.saseApi, self.saseToken, self.contentType, self.saseAuthHeaders)
			paLocations.paLocationsListLocations()
		else:
			print("Please request new token and create new prismaAccess object.")

	def paAddressGroupsListAddressGroups(self, __folder="Shared"):
		"""List all the address groups."""
		if self.checkTokenStillValid():
			paAddressGroup = addressGroups.addressGroups(self.saseApi, self.saseToken, self.contentType, self.saseAuthHeaders)
			paAddressGroup.paAddressGroupsListAddressGroups(__folder)
		else:
			print("Please request new token and create new prismaAccess object.")

	def paAddressGroupsCreate(self, __addressGroupObject, __folder="Shared"):
		"""Create an address group object"""
		if self.checkTokenStillValid():
			paAddressGroup = addressGroups.addressGroups(self.saseApi, self.saseToken, self.contentType, self.saseAuthHeaders)
			paAddressGroup.paAddressGroupsCreate(__addressGroupObject, __folder)
		else:
			print("Please request new token and create new prismaAccess object.")

	def paServiceConnectionsListServiceConnections(self, __folder="Service Connections"):
		"""List all service connections that are defined."""
		if self.checkTokenStillValid():
			paServiceConnection = serviceConnections.serviceConnections(self.saseApi, self.saseToken, self.contentType, self.saseAuthHeaders)
			paServiceConnection.paServiceConnectionsListServiceConnections(__folder)
		else:
			print("Please request new token and create new prismaAccess object.")

	def paIpsecTunnelsListIpsecTunnels(self, __folder="Service Connections"):
		"""List all IPSec Tunnels that are defined."""
		if self.checkTokenStillValid():
			paIpsecTunnels = ipsecTunnels.ipsecTunnels(self.saseApi, self.saseToken, self.contentType, self.saseAuthHeaders)
			paIpsecTunnels.paIpsecTunnelsListIpsecTunnels(__folder)
		else:
			print("Please request new token and create new prismaAccess object.")

	def paIkeGatewaysListIkeGateways(self, __folder="Service Connections"):
		"""
		List all IKE Gateways that are defined.
		Defaults to Service Connections folder.
		"""
		if self.checkTokenStillValid():
			paIkeGateways = ikeGateways.ikeGateways(self.saseApi, self.saseToken, self.contentType, self.saseAuthHeaders)
			paIkeGateways.paIkeGatewaysListIkeGateways(__folder)
		else:
			print("Please request new token and create new prismaAccess object.")

	def paIkeCryptoProfilesListIkeCryptoProfiles(self, __folder="Service Connections"):
		"""List all IKE Crypto Profiles that are defined."""
		if self.checkTokenStillValid():
			paIkeCryptoProfiles = ikeCryptoProfiles.ikeCryptoProfiles(self.saseApi, self.saseToken, self.contentType, self.saseAuthHeaders)
			paIkeCryptoProfiles.paIkeCryptoProfilesListIkeCryptoProfiles(__folder)
		else:
			print("Please request new token and create new prismaAccess object.")

	def __init__(self, __saseToken):
		"""Initialize Class"""
		self.saseApi = "https://api.sase.paloaltonetworks.com"
		self.saseToken = __saseToken
		self.contentType = "application/json"
		self.saseAuthHeaders = { 
			"Authorization": f"Bearer {self.saseToken['bearerToken']}",
			"Content-Type": f"{self.contentType}"
		}