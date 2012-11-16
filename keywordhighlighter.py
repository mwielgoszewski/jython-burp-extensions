# -*- coding: utf-8 -*-
'''
KeywordHighlighter
~~~~~~~~~~~~~~~~~~

This plugin highlights request objects in Burp Proxy and Intruder History
if one or more keywords is contained in the response
'''
from gds.burp.config import BoolOption, ListOption, Option
from gds.burp.core import Component, implements
from gds.burp.api import IProxyResponseHandler, IIntruderResponseHandler


class KeywordHighlighter(Component):
    implements(IProxyResponseHandler, IIntruderResponseHandler)

    keywords = ListOption('keyword-highlighter', 'keywords',
        '''Search response body and highlight request object if contains
        one of these keywords''')

    color = Option('keyword-highlighter', 'color', 'red',
        '''Highlight request object with this color''')

    case_sensitive = BoolOption('keyword-highlighter', 'case_sensitive', False,
        '''Search keywords in case sensitive manner, default is False''')

    def processResponse(self, request):
        matched_keywords = []

        for keyword in self.keywords:
            if self.case_sensitive is True and \
                keyword in request.response.body:
                    matched_keywords.append(keyword)

            elif self.case_sensitive is False and \
                keyword.lower() in request.response.body.lower():
                    matched_keywords.append(keyword)

        if matched_keywords:
            self.log.info('Response %s matched keywords: %s',
                          request.url.geturl(), ', '.join(matched_keywords))

            request.comment = ', '.join(matched_keywords)
            request.highlight = self.color

        return
