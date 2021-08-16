from burp import IBurpExtender, ICookie
from java.io import PrintWriter

class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks( self, callbacks):
        extName = "Delete Cookies"
        # keep a reference to our callbacks object and add helpers
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName(extName)

        # obtain our output streams
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)

        cookies = self._callbacks.getCookieJarContents()
        for cookie in cookies:
            new_cookie = Cookie(cookie.getDomain(), cookie.getName(), None, cookie.getPath(), cookie.getExpiration())
            self._callbacks.updateCookieJar(new_cookie)
            self._stdout.println("Cookie deleted!")

class Cookie(ICookie):
    def getDomain(self):
        return self.cookie_domain

    def getPath(self):
        return self.cookie_path

    def getExpiration(self):
        return self.cookie_expiration

    def getName(self):
        return self.cookie_name

    def getValue(self):
        return self.cookie_value

    def __init__(self, cookie_domain=None, cookie_name=None, cookie_value=None, cookie_path=None, cookie_expiration=None):
        self.cookie_domain = cookie_domain
        self.cookie_name = cookie_name
        self.cookie_value = cookie_value
        self.cookie_path = cookie_path
        self.cookie_expiration = cookie_expiration
