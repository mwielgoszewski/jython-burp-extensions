# -*- coding: utf-8 -*-
from gds.burp.api import *
from gds.burp.core import Component, implements

class UnhandledExceptionLogger(Component):
    '''
    This plugin logs all 500-level HTTP internal server errors to a
    host-specific log file.
    '''
    implements(IIntruderResponseHandler, IProxyResponseHandler,
               IRepeaterResponseHandler, IScannerResponseHandler)

    def __init__(self):
        self.logfiles = {}

    def __del__(self):
        for handle in self.logfiles.itervalues():
            try:
                handle.close()
            except Exception:
                pass

    def _open_logfile(self, hostname)
        return open('%s-errors.log' % (hostname,), 'ab')

    def write(self, host, data):
        of = self.logfiles.setdefault(host, self._open_logfile(host))

        of.write('\n=======================================================\n')
        of.write(data)
        of.write('\n=======================================================\n\n')
        return

    def processResponse(self, request):
        if request.status_code >= 500:
            self.write(request.host, request.raw)
            self.write(request.host, request.response.raw)
