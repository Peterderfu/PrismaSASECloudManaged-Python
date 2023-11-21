from datetime import datetime
from . import saseApi

class identityServices:
	"""identityServices class"""

	def checkTokenStillValid(self):
		"""
		Checks to see if the token is still valid. 
		Returns true is still in 15minute window. 
		Returns false if not.
		"""
		rightNow = datetime.now()
		tokenValid = bool(rightNow < self.prismaAccessObject.saseToken['expiresOn'])
		return tokenValid
	def paIdentidyListLocalUsers(self, __folder="Shared"):
		output = None
		if self.checkTokenStillValid():
			api = saseApi.saseApi(self.prismaAccessObject.localUsersUri, self.prismaAccessObject.saseToken, self.prismaAccessObject.contentType, self.prismaAccessObject.saseAuthHeaders)
			output = api.paList(__folder)
		else:
			print("Please request new token and create new prismaAccess object.")
		return output
	def paIdentityLockLocalUsers(self, __localUserObject, __folder="Shared"):
		output = None
		if self.checkTokenStillValid():
			api = saseApi.saseApi(self.prismaAccessObject.localUsersUri, self.prismaAccessObject.saseToken, self.prismaAccessObject.contentType, self.prismaAccessObject.saseAuthHeaders)
			output = api.paEdit(__localUserObject, "All")
		else:
			print("Please request new token and create new prismaAccess object.")
		return output
	def __init__(self, __prismaAccessObject):
		"""identityServices class initialization"""
		self.prismaAccessObject = __prismaAccessObject