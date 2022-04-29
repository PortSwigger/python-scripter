from abc import abstractmethod
from time import time
from java.beans import PropertyChangeSupport, PropertyChangeEvent

import sys
import traceback

DEFAULT_SCRIPT = '''# Recommended to use the pyscripter-er base script found here https://github.com/lanmaster53/pyscripter-er
# to be placed into the python environment directory

# from pyscripterer import BaseScript as Script

# args = [extender, callbacks, helpers, toolFlag, messageIsRequest, messageInfo, macroItems]

# script = Script(*args)
# script.help()
'''

class ObservableCollection(object):
    
    ITEM_ADDED = 2
    ITEM_REMOVED = 1

    def __init__(self):
        self.listeners = []

    @abstractmethod
    def add(self, obj):  # implemented by subclass
        raise NotImplementedError()

    @abstractmethod
    def remove(self, obj):  # implemented by subclass
        raise NotImplementedError()

    def add_listener(self, listener):
        self.listeners.append(listener)

    def remove_listener(self, listener):
        self.listeners.remove(listener)

    def _fireChangedEvent(self, type, obj):
        for listener in self.listeners:
            listener.collection_changed(self, type, obj)


class JavaBean(object):

    def __init__(self):
        self._changeSupport = None

    def addPropertyChangeListener(self, *args):
        if not self._changeSupport:
            self._changeSupport = PropertyChangeSupport(self)
        self._changeSupport.addPropertyChangeListener(*args)

    def removePropertyChangeListener(self, *args):
        if self._changeSupport:
            self._changeSupport.removePropertyChangeListener(*args)

    def firePropertyChange(self, propertyName, oldValue, newValue):
        if self._changeSupport:
            event = PropertyChangeEvent(self, propertyName, oldValue, newValue)
            self._changeSupport.firePropertyChange(event)

    def getPropertyChangeListeners(self, *args):
        if self._changeSupport:
            return self._changeSupport.getPropertyChangeListeners(*args)
        return []

    def hasListeners(self, *args):
        if self._changeSupport:
            return self._changeSupport.hasListeners(*args)
        return False


class ScriptCollection(ObservableCollection):
    
    def __init__(self):
        super(ScriptCollection, self).__init__()
        self.scripts = []

    def add(self, script):
        self.scripts.append(script)
        self._fireChangedEvent(ObservableCollection.ITEM_ADDED, script)

    def remove(self, script):
        self.scripts.remove(script)
        self._fireChangedEvent(ObservableCollection.ITEM_REMOVED, script)

    def to_dict(self):
        return {
            'created_at': int(time()),
            'scripts': [script.to_dict() for script in self.scripts] 
        }

    def from_dict(self, val, callbacks, helpers, extender):
        for script in val['scripts']:
            self.add(Script.from_dict(script, callbacks, helpers, extender))

    def __getitem__(self, index):
        return self.scripts[index]

    def __len__(self):
        return len(self.scripts)

    def __iter__(self):
        return self.scripts

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo, macroItems=[]):
        for script in self.scripts:
            script.processHttpMessage(toolFlag, messageIsRequest, messageInfo, macroItems)


class Script(JavaBean):

    def __init__(self, extender, callbacks, helpers, title, enabled=False, content=DEFAULT_SCRIPT):
        super(Script, self).__init__()
        self.title = title
        self.enabled = enabled
        self.callbacks = callbacks
        self.helpers = helpers
        self.extender = extender
        self.content = content
        self.stderr = sys.stderr
        self.stdout = sys.stdout
        self.state = dict()
        self._code = None
        self._compiled_content = content
        self._compilation_error = ''
        self._is_compiled = False

    def to_dict(self):
        fields = ['title', 'enabled', 'content']
        return { field: getattr(self, field) for field in fields}
        
    def compile(self):
        try:
            self._code = None
            self._compiled_content = self.content
            self._code = compile(self.content, '<string>', 'exec')
            self.is_compiled = True
        except:
            self.is_compiled = False
            self._compilation_error = traceback.format_exc()
            self.firePropertyChange(Script.Properties.COMPILATION_ERROR, '', self._compilation_error)
            
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo, macroItems=[]):
        if self.enabled and self._code:
            locals_ = {}
            globals_  = {'extender': self.extender,
                        'callbacks': self.callbacks,
                        'helpers': self.helpers,
                        'toolFlag': toolFlag,
                        'messageIsRequest': messageIsRequest,
                        'messageInfo': messageInfo,
                        'macroItems': macroItems,
                        'state': self.state
                    }

            oldstderr = sys.stderr
            oldstdout = sys.stdout
            sys.stdout = self.stdout
            sys.stderr = self.stderr
            try:
                exec(self._code, globals_, locals_)
            except:
                self.stderr.write(traceback.format_exc())
            finally:
                sys.stdout = oldstdout
                sys.stderr = oldstderr

    @property
    def requires_compile(self):
        return self.content != self._compiled_content

    @property
    def compilation_error(self):
        return self._compile_error
    
    @property
    def is_compiled(self):
        return self._is_compiled

    @is_compiled.setter
    def is_compiled(self, val):
        old_val = self._is_compiled
        self._is_compiled = val
        self.firePropertyChange(Script.Properties.IS_COMPILED, old_val, self._is_compiled)

    @classmethod
    def from_dict(cls, val, callbacks, helpers, extender):
        return Script(extender, 
            callbacks, 
            helpers, 
            val['title'], 
            val['enabled'], 
            val['content'])

    class Properties:

        COMPILATION_ERROR = 'compilation_error'
        IS_COMPILED = 'is_compiled'
