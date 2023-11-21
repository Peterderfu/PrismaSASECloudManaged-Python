from datetime import datetime
from . import saseApi

class configurationManagement:
	"""configurationManagement class"""

	def checkTokenStillValid(self):
		"""
		Checks to see if the token is still valid. 
		Returns true is still in 15minute window. 
		Returns false if not.
		"""
		rightNow = datetime.now()
		tokenValid = bool(rightNow < self.prismaAccessObject.saseToken['expiresOn'])
		return tokenValid
	def paConfigPush(self,__configPushObject,__folder="Shared"):
		output = None
		if self.checkTokenStillValid():
			api = saseApi.saseApi(self.prismaAccessObject.configPushUri, self.prismaAccessObject.saseToken, self.prismaAccessObject.contentType, self.prismaAccessObject.saseAuthHeaders)
			output = api.paCreate(__configPushObject, __folder)
		else:
			print("Please request new token and create new prismaAccess object.")
		return output
	def __init__(self, __prismaAccessObject):
		"""configurationManagement class initialization"""
		self.prismaAccessObject = __prismaAccessObject