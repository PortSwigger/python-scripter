from java.util import EventObject, EventListener
from javax.swing import JTextArea, JButton, JPanel,JLabel, JTextField, SwingUtilities
from javax.swing.event import EventListenerList
from java.awt.event import MouseAdapter, FocusListener, KeyEvent
from java.awt import Color

class TabComponent(JPanel):    

    def __init__(self):
        self.opaque = False
        self._tabbed_pane = None

    def addTitle(self, title):
        label = JLabel(title)
        self.add(label)

    @property
    def tabbed_pane(self):
        return self._tabbed_pane

    @tabbed_pane.setter
    def tabbed_pane(self, tabbed_pane):
        self._tabbed_pane = tabbed_pane


class TabComponentClosedEvent(EventObject):

    def __init__(self, source):
        # super(TabComponentClosedEvent, self).__init__(source) not sure why but this does not work :-/
        EventObject.__init__(self, source)

class TabComponentCloseListener(EventListener):
    def tabClose(event):
        pass

class TabComponentCloseableMixin(object):
    
    def __init__(self):
        self.listeners = EventListenerList()
        self.close_button = JButton(actionPerformed=self._clicked)
        self.close_button.setText(unichr(0x00d7))  # multiplication sign
        self.close_button.border = None
        self.close_button.contentAreaFilled = False
        self.close_button.addMouseListener(TabComponentCloseableMixin.EventListener(self))
        self.add(self.close_button)
        super(TabComponentCloseableMixin, self).__init__()
        
    def addCloseListener(self, listener):
        self.listeners.add(TabComponentCloseListener, listener)

    def removeCloseListener(self, listener):
        self.listeners.remove(TabComponentCloseListener, listener)

    def mouseEntered(self, event):
        self.close_button.foreground = Color.red

    def mouseExited(self, event):
        self.close_button.foreground = Color.black

    def _clicked(self, event):   
        event = TabComponentClosedEvent(self)
        for listener in self.listeners.getListeners(TabComponentCloseListener):
            listener.tabClose(event)

    class EventListener(MouseAdapter):

        def __init__(self, parent):
            self.parent = parent

        def mouseEntered(self, event):
            self.parent.mouseEntered(event)

        def mouseExited(self, event):
            self.parent.mouseExited(event)


class TabComponentTitleChangedEvent(EventObject):

    def __init__(self, source, title):
        # super(TabComponentTitleChangedEvent, self).__init__(source) not sure why but this does not work :-/
        EventObject.__init__(self, source)
        self._title = title

    def getTitle(self):
        return self._title
        

class TabComponentTitleChangedListener(EventListener):
    def titleChanged(event):
        pass

class TabComponentEditableTabMixin(object):
    
    def __init__(self):
        self.listeners = EventListenerList()
        self.isEditing = False
        self.event_listener = TabComponentEditableTabMixin.EventListener(self)
        self.text_field = TabTextField()
        self.text_field.actionPerformed = self.submitted
        self.text_field.keyPressed = self.keyPressed
        self.text_field.addMouseListener(self.event_listener)
        self.text_field.addFocusListener(self.event_listener)
        self.addMouseListener(self.event_listener)
        self.addFocusListener(self.event_listener)
        self.add(self.text_field)
        super(TabComponentEditableTabMixin, self).__init__()
    
    def addTitleChangedListener(self, listener):
        self.listeners.add(TabComponentTitleChangedListener, listener)

    def removeTitleChangedListener(self, listener):
        self.listeners.remove(TabComponentTitleChangedListener, listener)

    def fireTitleChanged(self):   
        event = TabComponentTitleChangedEvent(self, self.text_field.text)
        for listener in self.listeners.getListeners(TabComponentTitleChangedListener):
            listener.titleChanged(event)
    
    @property
    def text(self):
        return self.text_field.text

    @text.setter
    def text(self, text):
        self.text_field.text = text

    def setEditing(self, state):
        self.isEditing = state
        if self.isEditing:
            self._text = self.text_field.text  # save text in case need to revert
            self.text_field.enableEditing()
        else:
            self.text_field.disableEditing()

    def mouseClicked(self, event):
        if SwingUtilities.isLeftMouseButton(event) and event.clickCount == 2:
            if not self.isEditing:
                self.setEditing(True)
        elif SwingUtilities.isLeftMouseButton(event) and event.clickCount == 1:
            idx = self.tabbed_pane.indexOfTabComponent(self)
            self.tabbed_pane.selectedIndex = idx

    def keyPressed(self, event):
        if event.keyCode == KeyEvent.VK_ESCAPE:
            self.text = self._text  # set the text back
            self.setEditing(False)

    def submitted(self,event):
        self.setEditing(False)
        self.fireTitleChanged()

    def focusLost(self, event):
        self.setEditing(False)
        self.fireTitleChanged()

    class EventListener(MouseAdapter, FocusListener):
        
        def __init__(self, parent):
            self.parent = parent

        def mouseClicked(self, event):
            self.parent.mouseClicked(event)

        def focusGained(self, event):  # only required as multiple inheritance is not allowed on java classes
            pass

        def focusLost(self, event):
            self.parent.focusLost(event)


class TabTextField(JTextField):

    def __init__(self):
        JTextField.__init__(self)
        self.editable = False
        self.border = None    
        self.opaque = False
    
    def enableEditing(self):
        self.editable = True
        self.opaque = True
        self.caret.visible = True  # have to micro manage the caret
    
    def disableEditing(self):
        self.editable = False
        self.opaque = False
        self.caret.visible = False # have to micro manage the caret

    # required to allow tab to grow while editing
    def isValidateRoot(self):
        return False


class BurpUI():

    @staticmethod
    def _find_textarea(parent):
        # keep searching down the tree till we find 
        for child in parent.getComponents():
            if isinstance(child, JTextArea):
                return child
            return BurpUI._find_textarea(child)

        raise RuntimeError('Could not find JTextArea.')

    @staticmethod
    def get_textarea(editor):
        # help retrieve the main editor JTextArea component from the built-in Burp ITextEditor returned from callbacks.createTextEditor()
        # saves having to remember the component position in the arrays
        component = editor.component
        return BurpUI._find_textarea(component.getComponents()[1])