
from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from burp import IParameter

import xml.dom.minidom

class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    def	registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("SAPEVENTQUEUE Decoder")
        
        # register ourselves as a message editor tab factory
        callbacks.registerMessageEditorTabFactory(self)
        
        return
        
    def createNewInstance(self, controller, editable):
        # create a new instance of our custom editor tab
        return SAPEventQueueInputTab(self, controller, editable)

class SAPEventQueueInputTab(IMessageEditorTab):
    TAB_CAPTION = "SAPEVENTQUEUE"

    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._editable = False

        self._txtInput = extender._callbacks.createTextEditor()
        self._txtInput.setEditable(editable)
        return
        
    def getTabCaption(self):
        return SAPEventQueueInputTab.TAB_CAPTION
        
    def getUiComponent(self):
        return self._txtInput.getComponent()
        
    def isEnabled(self, content, isRequest):
        # enable this tab for requests containing the parameter
        res = isRequest and not self._extender._helpers.getRequestParameter(content, "SAPEVENTQUEUE") is None
        print("[SAPEventQueueInputTab] [isEnabled] {}".format(res))
        
        return res

    def setMessage(self, content, isRequest):
        if (content is None):
            # clear our display
            self._txtInput.setText(None)
            self._txtInput.setEditable(False)
        
        else:
            # retrieve the data parameter
            parameter = self._extender._helpers.getRequestParameter(content, "SAPEVENTQUEUE")
            
            value = parameter.getValue().encode('utf-8')
            print("[SAPEventQueueInputTab] [setMessage] {}".format(value))

            event  = SAPEvent(value)
            output = event.get_pretty_message()
            print("[SAPEventQueueInputTab] [setMessage] {}".format(output))

            # deserialize the parameter value
            self._txtInput.setText(output)
            self._txtInput.setEditable(self._editable)
            #TODO: set content_type_xml
            #   see https://portswigger.net/burp/extender/api/burp/IRequestInfo.html#CONTENT_TYPE_XML
        
        # remember the displayed content
        self._currentMessage = content
        return
    
    def getMessage(self):
        return self._currentMessage
    
        # determine whether the user modified the deserialized data
        if (self._txtInput.isTextModified()):
            # reserialize the data
            text = self._txtInput.getText()
            input = self._extender._helpers.urlEncode(self._extender._helpers.base64Encode(text))
            
            # update the request with the new parameter value
            return self._extender._helpers.updateParameter(self._currentMessage, self._extender._helpers.buildParameter("data", input, IParameter.PARAM_BODY))
            
        else:
            return self._currentMessage
    
    def isModified(self):
        return self._txtInput.isTextModified()
    
    def getSelectedData(self):
        return self._txtInput.getSelectedText()
            

class SAPEvent(object):
    Event            = '~E001'
    Section_Begin    = '~E002'
    Section_End      = '~E003'
    Keyvalue         = '~E004'
    Keyvalue_Pair    = '~E005'
    Collection_Entry = '~E006'

    def __init__(self, content):
        print("[SAPEvent] [init] {}".format(content))
        self.raw_message = self._parse_content(content)
        
        return
    
    def get_pretty_message(self):
        print("[SAPEvent] [get_pretty_message] {}".format(self.raw_message))

        xml_dom = xml.dom.minidom.parseString(self.raw_message)
        return xml_dom.toprettyxml(indent='\t')

    def _parse_content(self, content):
        print("[SAPEvent] [_parse_content] {}".format(content))

        #FIXME: better serialized parsing
        output = '<sapeventqueue>'
        # split SAPEvent.Event
        events = content.split(SAPEvent.Event)
        for event in events:
            # Split Sections and remove Section_End
            sections = event.replace(SAPEvent.Section_End,"").split(SAPEvent.Section_Begin)
            
            # Create event
            output += '<event name="{}">'.format(sections[0])
            for x in sections[1:]:
                output += '<section>'
                kv = list()
                for r in x.split(SAPEvent.Keyvalue_Pair):
                    kvx = r.split(SAPEvent.Keyvalue)
                    print("[SAPEvent] [_parse_content] {}".format(kvx))
                    if len(kvx) == 2:
                        output += '<keyvalue>'
                        output += '<key>{}</key>'.format(kvx[0])
                        output += '<value>{}</value>'.format(kvx[1])
                        output += '</keyvalue>'

                    r = r.replace(SAPEvent.Keyvalue,"=")
                    kv.append(r)

                # Concatenate KeyValue pairs
                #output += "&".join(kv)
                # Terminate section
                output += '</section>'
            
            output += "</event>\r\n"
        output += "</sapeventqueue>"

        return output
