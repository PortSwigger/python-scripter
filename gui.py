from javax.swing import JTabbedPane, JPanel, JButton, JLabel, SwingConstants, BorderFactory, JOptionPane, GroupLayout, JCheckBox, JSplitPane, JRadioButton, ButtonGroup, JFileChooser
from javax.swing.event import ChangeListener, DocumentListener
from javax.swing.LayoutStyle.ComponentPlacement import RELATED, UNRELATED
from java.awt import BorderLayout, Font, Component, Color
from java.beans import PropertyChangeListener
from org.python.core.util import StringUtil
from burp import IExtensionStateListener
from uicomponents import BurpUI, TabComponent, TabComponentEditableTabMixin, TabComponentCloseableMixin, TabComponentCloseListener, TabComponentTitleChangedListener
from models import ObservableCollection, Script
from utils import EditorFileAdapter


class ScriptTabbedPane(JTabbedPane):
    
    EMPTY_SCRIPT_TEXT  = '''<html><body>
<div style="font-size: 16pt;text-align:center">
You have no Python scripts created.<br/> Please use the add tab (+) button to create a new Python script.
</div></body></html>'''

    def __init__(self, extender, callbacks, helpers, scripts):
        super(ScriptTabbedPane, self).__init__()
        self.scripts = scripts
        self.extender = extender
        self.callbacks = callbacks
        self.helpers = helpers

        self.addChangeListener(ScriptTabbedPane.TabsStateChanged())
        self.scripts.add_listener(self)
        self.create_add_tab()

    def create_add_tab(self):
        self.add_tab = JButton("+", actionPerformed=self.add_clicked)
        self.add_tab.font = Font('Monospaced', Font.PLAIN, 18)
        self.add_tab.contentAreaFilled = False
        self.add_tab.border = None
        
        self.emptyTab = JPanel(BorderLayout())
        self.emptyTab.add(JLabel(ScriptTabbedPane.EMPTY_SCRIPT_TEXT, SwingConstants.CENTER), BorderLayout.CENTER)

        self.addTab(None, self.emptyTab)
        self.setTabComponentAt(0, self.add_tab)

    def add_clicked(self, event):
        idx = self.tabCount - 1
        title = 'New Script {}'.format(idx + 1)
        script = Script(self.extender, self.callbacks, self.helpers, title)
        self.scripts.add(script)

    def create_script_tab(self, script, idx):
        new_tab = ScriptTabComponent(script)
        new_tab.tabbed_pane = self
        new_tab.addCloseListener(ScriptTabbedPane.ScriptTabCloseListener(self, self.scripts, script))
        new_tab.addTitleChangedListener(ScriptTabbedPane.ScriptTabTabTitleChangedListener(script))
        new_panel = ScriptPanel(script, self.callbacks)
        self.add(new_panel, idx)
        self.setTabComponentAt(idx, new_tab)
        self.selectedIndex = idx

    def collection_changed(self, collection, type, script):
        if type == ObservableCollection.ITEM_ADDED:
            idx = self.tabCount - 1
            self.create_script_tab(script, idx)


    class ScriptTabCloseListener(TabComponentCloseListener):

        def __init__(self, tabbedpane, scripts, script):
            self.tabbed_pane = tabbedpane 
            self.scripts = scripts
            self.script = script

        def tabClose(self, event):
            result = JOptionPane.showConfirmDialog(None, 'Are you sure you want to close \'{}\' ?'.format(event.source.text), 
                                                "Close Tab", 
                                                JOptionPane.YES_NO_OPTION, 
                                                JOptionPane.QUESTION_MESSAGE)
            if result == JOptionPane.YES_OPTION:        
                idx = self.tabbed_pane.indexOfTabComponent(event.source)
                self.tabbed_pane.remove(idx)
                self.scripts.remove(self.script)

    class ScriptTabTabTitleChangedListener(TabComponentTitleChangedListener):

        def __init__(self, script):
            self.script = script

        def titleChanged(self, event):
            self.script.title = event.getTitle()


    class TabsStateChanged(ChangeListener):
        
        def stateChanged(self, event):
            # prevents the add tab from being selected apart from when there are no other tabs created (i.e. starting from fresh)
            # instead the tab next the add tab is selected
            tabbed_pane = event.source
            if tabbed_pane.tabCount > 1 and tabbed_pane.selectedIndex == tabbed_pane.tabCount - 1:
                tabbed_pane.selectedIndex = tabbed_pane.tabCount - 2


class ScriptTabComponent(TabComponentEditableTabMixin, TabComponentCloseableMixin, TabComponent):
    
    def __init__(self, script):
        super(ScriptTabComponent, self).__init__()
        self.script = script
        self.text = self.script.title
        self.close_button.font = Font('Dialog', Font.PLAIN, 16)
        self.text_field.toolTipText = self.toolTipText = 'Double click to rename, Enter to confirm or Esc to cancel'

    

class ScriptEditingPanel(JPanel, DocumentListener):

    def __init__(self, callbacks, script):
        super(ScriptEditingPanel, self).__init__()
        self.callbacks = callbacks
        self.script = script
        self.enabledCheckbox = JCheckBox('Enabled', self.script.enabled, itemStateChanged=self.enabled_changed, alignmentX=Component.LEFT_ALIGNMENT)
        self.scriptEditor = callbacks.createTextEditor()
        self.scriptEditor.text = script.content
        self.scriptText = self.scriptEditor.component
        self.compileButton = JButton('Compile', actionPerformed=self.compile, enabled=False)
        
        editingLayout = GroupLayout(self, autoCreateGaps=True, autoCreateContainerGaps=True)
        editingLayout.setHorizontalGroup(editingLayout.createParallelGroup()
                                            .addGroup(editingLayout.createSequentialGroup()
                                                .addComponent(self.enabledCheckbox)
                                                .addPreferredGap(UNRELATED)
                                            )
                                            .addGroup(editingLayout.createParallelGroup()
                                              .addComponent(self.scriptText)
                                              .addComponent(self.compileButton)
                                            )
                                        )

        editingLayout.setVerticalGroup(editingLayout.createSequentialGroup()
                                            .addGroup(editingLayout.createParallelGroup()
                                                .addComponent(self.enabledCheckbox)
                                            )
                                            .addGroup(editingLayout.createSequentialGroup()
                                                .addComponent(self.scriptText)
                                                .addComponent(self.compileButton) 
                                            )
                                        )
        self.layout = editingLayout
        BurpUI.get_textarea(self.scriptEditor).document.addDocumentListener(self)
        self.compile(None)

    def enabled_changed(self, event):
        self.script.enabled = self.enabledCheckbox.isSelected()

    def compile(self, event):
        self.script.compile()
        self.compileButton.enabled = False

    def changedUpdate(self, event):
        self._update_content()
        self._can_compile(event)

    def insertUpdate(self, event):
        self._update_content()
        self._can_compile(event)
    
    def removeUpdate(self, event):
        self._update_content()
        self._can_compile(event)

    def _update_content(self):
        self.script.content = StringUtil.fromBytes(self.scriptEditor.text)

    def _can_compile(self, event):
        self.compileButton.enabled = False
        if event.document.length > 0:
            self.compileButton.enabled = self.script.requires_compile


class ScriptOutputPanel(JPanel, PropertyChangeListener, IExtensionStateListener):
            
    def __init__(self, callbacks, script):
        super(ScriptOutputPanel, self).__init__()
        self.callbacks = callbacks
        self.script = script
        self.script.addPropertyChangeListener(self)
        self.tabbedPane = JTabbedPane()
        self._create_output_panel()
        self._create_error_panel()
        self.tabbedPane.addTab('Output', self.outputPanel)
        self.tabbedPane.addTab('Errors', self.errorPanel)
        self.layout = BorderLayout()
        self.add(self.tabbedPane, BorderLayout.CENTER)
        self.script.stdout = EditorFileAdapter(self.outputEditor)
        self.script.stderr = EditorFileAdapter(self.errorEditor)
        self.output_file = None
        
        # register to be notified when the extension is unloaded so if a output_file ref is in use it can be closed
        callbacks.registerExtensionStateListener(self)

    def clear_stderr(self, event):
        self.errorEditor.text = ''
        
    def clear_stdout(self, event):
        self.outputEditor.text = ''

    def save_file_output(self, event):
        self.outputFileBrowseButton.enabled = True
        if self.output_file:  # already have an output_file
            self.script.stdout = self.output_file
            return

        if not self.set_output_file():
            # didn't choose a file then revert to using UI
            self.outputUIRadioButton.selected = True
    
    def view_ui_output(self, event):
        self.outputFileBrowseButton.enabled = False
        self.script.stdout = EditorFileAdapter(self.outputEditor)

    def set_output_file(self, event=None):
        file_chooser = JFileChooser()
        choice = file_chooser.showSaveDialog(None)
        if choice == JFileChooser.APPROVE_OPTION:
            self.outputFileLabel.text = file_chooser.selectedFile.path
            self.output_file = open(file_chooser.selectedFile.path, 'a')         
            self.script.stdout = self.output_file
            return True
        
        return False
        
    def propertyChange(self, event):
        if event.propertyName == Script.Properties.IS_COMPILED:
             if event.newValue:
                self.errorEditor.text = ''
        elif event.propertyName == Script.Properties.COMPILATION_ERROR:
            self.errorEditor.text = event.newValue
            self.tabbedPane.selectedIndex = 1          

    def extensionUnloaded(self):
        if self.output_file:  # if we have a file ref then close it
            print('Closing output file reference')
            self.output_file.close()

    def _create_output_panel(self):
        self.outputPanel = JPanel()
        self.outputEditor = self.callbacks.createTextEditor()
        self.outputEditor.editable = False
        self.outputText = self.outputEditor.component
        self.clearOutputButton = JButton('Clear', actionPerformed=self.clear_stdout)
        self.outputButtonGroup = ButtonGroup()
        self.outputFileRadioButton = JRadioButton('Save to File:', actionPerformed=self.save_file_output)
        self.outputUIRadioButton = JRadioButton('Show in UI:', selected=True, actionPerformed=self.view_ui_output)
        self.outputFileLabel = JLabel()
        self.outputFileBrowseButton  = JButton('Browse...', enabled=False, actionPerformed=self.set_output_file)

        self.outputButtonGroup.add(self.outputFileRadioButton)
        self.outputButtonGroup.add(self.outputUIRadioButton)

        outputLayout = GroupLayout(self.outputPanel, autoCreateGaps=True, autoCreateContainerGaps=True)
        outputLayout.setHorizontalGroup(outputLayout.createParallelGroup()
                                            .addGroup(
                                                outputLayout.createSequentialGroup()
                                                    .addComponent(self.outputFileRadioButton)
                                                    .addComponent(self.outputFileLabel)
                                                    .addComponent(self.outputFileBrowseButton)
                                                )
                                            .addComponent(self.outputUIRadioButton)
                                            .addComponent(self.outputText)
                                            .addComponent(self.clearOutputButton)  
                                        )

        outputLayout.setVerticalGroup(outputLayout.createSequentialGroup()
                                        .addGroup(
                                            outputLayout.createParallelGroup()
                                                .addComponent(self.outputFileRadioButton)
                                                .addComponent(self.outputFileLabel)
                                                .addComponent(self.outputFileBrowseButton)
                                            )
                                        .addComponent(self.outputUIRadioButton)
                                        .addComponent(self.outputText)
                                        .addComponent(self.clearOutputButton)   
                                        )
        self.outputPanel.layout = outputLayout
        
    def _create_error_panel(self):
        self.errorPanel = JPanel()
        self.errorEditor = self.callbacks.createTextEditor()
        self.errorEditor.editable = False
        self.errorText = self.errorEditor.component
        self.clearErrorButton = JButton('Clear', actionPerformed=self.clear_stderr)

        errorLayout = GroupLayout(self.errorPanel, autoCreateGaps=True, autoCreateContainerGaps=True)
        errorLayout.setHorizontalGroup(errorLayout.createParallelGroup()
                                            .addComponent(self.errorText)
                                            .addComponent(self.clearErrorButton)  
                                        )
        errorLayout.setVerticalGroup(errorLayout.createSequentialGroup()
                                            .addComponent(self.errorText)
                                            .addComponent(self.clearErrorButton)   
                                        )
        self.errorPanel.layout = errorLayout

class ScriptPanel(JPanel):

    def __init__(self, script, callbacks):
        self.script = script
        self.layout = BorderLayout()
        self.editingPanel = ScriptEditingPanel(callbacks, script)
        self.outputPanel = ScriptOutputPanel(callbacks, script)
        self.splitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT, dividerSize=10)
        self.splitPane.topComponent = self.editingPanel
        self.splitPane.bottomComponent = self.outputPanel
        self.add(self.splitPane, BorderLayout.CENTER)


class GUI(object):
    
    def __init__(self, extender, callbacks, helpers, scripts):
        self.panel = JPanel()
        self.tabs = ScriptTabbedPane(extender, callbacks, helpers, scripts)
        layout = BorderLayout()
        self.panel.setLayout(layout)
        self.panel.add(self.tabs)

    def build(self):
        return self.panel