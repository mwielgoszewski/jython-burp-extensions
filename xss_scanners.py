# -*- coding: utf-8 -*-
from gds.burp.api import IProxyResponseHandler, IRepeaterResponseHandler
from gds.burp.core import Component, implements

import re


# https://code.google.com/p/domxsswiki/wiki/FindingDOMXSS

DOM_XSS_SOURCE = re.compile(
    '''(location\s*[\[.])|([.\[]\s*["']?\s*(arguments|dialogArguments|innerHTML|write(ln)?|open(Dialog)?|showModalDialog|cookie|URL|documentURI|baseURI|referrer|name|opener|parent|top|content|self|frames)\W)|(localStorage|sessionStorage|Database)'''
    )

DOM_XSS_SINK = re.compile(
    '''((src|href|data|location|code|value|action)\s*["'\]]*\s*\+?\s*=)|((replace|assign|navigate|getResponseHeader|open(Dialog)?|showModalDialog|eval|evaluate|execCommand|execScript|setTimeout|setInterval)\s*["'\]]*\s*\()'''
    )

class DomXssScanner(Component):
    implements(IProxyResponseHandler, IRepeaterResponseHandler)

    def processResponse(self, request):
        for lineno, line in enumerate(request.response.body.splitlines()):
            if DOM_XSS_SOURCE.search(line):
                self.log.warn('DOM XSS Source identified (line %d): %s',
                              lineno, line.strip())

            if DOM_XSS_SINK.search(line):
                self.log.warn('DOM XSS Sink identified (line %d): %s',
                              lineno, line.strip())

        return
