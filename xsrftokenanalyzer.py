# -*- coding: utf-8 -*-
'''
XsrfTokenAnalyzer
~~~~~~~~~~~~~~~~~

This plugin highlights request objects in Burp Proxy History
if the request did not contain one of a specified known anti-XSRF tokens
'''
from gds.burp.config import BoolOption, ListOption, Option
from gds.burp.core import Component, implements
from gds.burp.api import IProxyRequestHandler

class XsrfTokenAnalyzer(Component):
    implements(IProxyRequestHandler)

    xsrf_token = Option('xsrf-token-analyzer', 'token_name', '_xsrf_token',
        '''The request parameter name of the anti-XSRF token''')

    exempt_methods = ListOption('xsrf-token-analyzer', 'exempt_methods',
        '''These HTTP methods do not require XSRF protection''')

    color = Option('xsrf-token-analyzer', 'color', 'orange',
        '''Highlight request with color if anti-XSRF token is missing''')

    in_scope_only = BoolOption('xsrf-token-analyzer', 'in_scope_only', False,
        '''Analyze in-scope requests only, default is False''')

    def processRequest(self, request):

        # skip processing if request is not in scope
        if self.in_scope_only and not self.burp.isInScope(request.url.geturl()):
            self.log.debug('Request not in scope %r', request)
            return

        # skip processing if request method is exempt from xsrf protection
        if request.method in self.exempt_methods:
            return

        if request.parameters:
            for ptype, parameters in request.parameters.iteritems():
                if self.xsrf_token in parameters:
                    # return early since xsrf token is contained in parameters
                    return

        self.log.warn('%s %s does not contain XSRF protection',
                      request.method, request.url.geturl())
        request.highlight = self.color
        return
