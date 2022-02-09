from burp import IBurpExtender, ISessionHandlingAction, IExtensionStateListener, IHttpListener, ITab, IBurpExtenderCallbacks
from models import ScriptCollection
from scriptstore import ScriptCollectionStore
from gui import GUI

import traceback

__NAME__ = 'Multi-py'


IBurpExtenderCallbacks.TOOL_MACRO = 0

class BurpExtender(IBurpExtender, ISessionHandlingAction, IExtensionStateListener, IHttpListener, ITab):

    def registerExtenderCallbacks(self, callbacks):
        print('Registering {}...'.format(__NAME__))
        self.callbacks = callbacks
        self.helpers = callbacks.helpers
        self.script_store = ScriptCollectionStore(callbacks, self.helpers, self)
        self.scripts = ScriptCollection()
        self.gui = GUI(self, self.callbacks, self.helpers, self.scripts)
        
        self.script_store.restore(self.scripts)

        callbacks.setExtensionName(__NAME__)
        callbacks.registerSessionHandlingAction(self)
        callbacks.registerExtensionStateListener(self)
        callbacks.registerHttpListener(self)
        # callbacks.customizeUiComponent(self.getUiComponent())
        callbacks.addSuiteTab(self)

        print('{} has been successfully registered'.format(__NAME__))

    def getActionName(self):
        return 'Send to Python Scripter'

    def extensionUnloaded(self):
        try:
            self.script_store.save(self.scripts)    
        except Exception:
            traceback.print_exc(file=self.callbacks.getStderr())
        return

    def performAction(self, currentRequest, macroItems):
        self.processHttpMessage(self.callbacks.TOOL_MACRO, 1, currentRequest, macroItems)
        return

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo, macroItems=[]):
        try:
            self.scripts.processHttpMessage(toolFlag, messageIsRequest, messageInfo, macroItems)
        except Exception:
            traceback.print_exc(file=self.callbacks.getStderr())
        return

    def getTabCaption(self):
        return 'Python Scripts'

    def getUiComponent(self):
        return self.gui.build()
