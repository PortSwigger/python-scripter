from org.python.core.util import StringUtil

'''

'''
class EditorFileAdapter(object):

    def __init__(self, editor):
        self.editor = editor
        
    def write(self, val):
        # print >> sys.stderr, val
        self.editor.text = self.editor.text + StringUtil.toBytes(val)
        