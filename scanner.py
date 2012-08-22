# -*- coding: utf-8 -*-
from gds.burp.api import IScannerRequestHandler, IScannerResponseHandler
from gds.burp.core import Component, implements

class ScannerLogger(Component):
    implements(IScannerRequestHandler, IScannerResponseHandler)

    def __init__(self):
        self.logfiles = {}

    def __del__(self):
        for handle in self.logfiles.itervalues():
            try:
                handle.close()
            except Exception:
                pass

    def write(self, host, data):
        of = self.logfiles.setdefault(host, open('%s-scanner.log' % (host,), 'ab'))
        of.write('=======================================================\n\n')
        of.write(data)
        of.write('\n=======================================================\n\n')
        return

    def processRequest(self, request):
        self.write(request.host, request.raw)

    def processResponse(self, request):
        self.write(request.host, request.response.raw)
