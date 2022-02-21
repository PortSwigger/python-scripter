import json
from models import ScriptCollection

class ScriptCollectionStore(object):

    _SAVE_NAME = 'script_store'

    def __init__(self, callbacks, helpers, extender):
        self.callbacks = callbacks
        self.helpers = helpers
        self.extender = extender

    def restore(self, scripts):
        json_string = self.callbacks.loadExtensionSetting(ScriptCollectionStore._SAVE_NAME)
        if json_string:
            print('Restored scripts:')
            print(json_string)
            loaded = json.loads(json_string)
            scripts.from_dict(loaded, self.callbacks, self.helpers, self.extender)

    def save(self, scripts):
        save = scripts.to_dict()
        json_string = json.dumps(save, indent=2)
        print('Saving scripts:')
        print(json_string)
        self.callbacks.saveExtensionSetting(ScriptCollectionStore._SAVE_NAME, json_string)