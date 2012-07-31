# -*- coding: utf-8 -*-
try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

from array import array

from gds.burp.models import HttpRequest
from gds.burp.menu import MenuItem
from gds.gwt.GWTParser import GWTParser


class GWTIntruderMenu(MenuItem):
    CAPTION = 'send to intruder (GWT request)'

    def menuItemClicked(self, menuItemCaption, messageInfo):
        for message in messageInfo:
            request = HttpRequest(message, _burp=self.burp)

            if not request.content_type.startswith('text/x-gwt-rpc'):
                continue

            body = StringIO()
            body.write(request.raw.split('\r\n\r\n', 1)[0])
            body.write('\r\n\r\n')

            try:
                message, offsets = getGWTInsertionPointOffsets(body, request.body)
            except Exception:
                self.burp.log.exception('Error getting insertion point '
                    'offsets for request: %r', request)
                continue

            self.burp.sendToIntruder(
                request.host, request.port, request.is_secure,
                message, offsets)

        return


class GWTActiveScanerMenu(MenuItem):
    CAPTION = 'actively scan this item (GWT request)'

    def menuItemClicked(self, menuItemCaption, messageInfo):
        for message in messageInfo:
            request = HttpRequest(message, _burp=self.burp)

            if not request.content_type.startswith('text/x-gwt-rpc'):
                continue

            body = StringIO()
            body.write(request.raw.split('\r\n\r\n', 1)[0])
            body.write('\r\n\r\n')

            try:
                message, offsets = getGWTInsertionPointOffsets(body, request.body)
            except Exception:
                self.burp.log.exception('Error getting insertion point '
                    'offsets for request: %r', request)
                continue

            self.burp.doActiveScan(
                request.host, request.port, request.is_secure,
                message, offsets)

        return


def getGWTInsertionPointOffsets(fileobj, rpc_string):
    '''
    Get the insertion point offsets for a GWT rpc string relative
    to the (request) object passed.

    :param fileobj: a file-like object (i.e., StringIO())
    :param rpc_string: the GWT-RPC payload to fuzz

    :returns: A tuple containing raw request string and a list of
    integer array's suitable to pass to :meth:`~BurpExtender.doActiveScan`
    and :meth:`~BurpExtender.sendToIntruder`.
    '''

    # offsets in Java needs to be of type List<int[2]>
    # Jython will coerce a list of array.array's with type 'i'
    # to List<int> properly.

    offsets = []

    gwt = GWTParser()
    gwt.deserialize(rpc_string)

    payload = gwt.rpc_string.rstrip('|').split('|')

    for idx, item in enumerate(payload):
        start = fileobj.tell()

        fileobj.write(item)

        # identify what items in the rpc string are suitable for
        # fuzzing, and append an int[2] to the offsets list denoting
        # the start and end position of a fuzzable item.
        #
        # e.g., ignore the version, hash, class, method and other
        # items in the rpc request that would throw a deserialization
        # exception if they're tampered with.

        if idx in gwt.fuzzmarked:
            offsets.append(array('i', (start, fileobj.tell())))

        fileobj.write('|')

    assert offsets, 'Insertion point offsets cannot be null'

    message = fileobj.getvalue()

    assert len(message) >= offsets[-1][1], \
        'Last offset %d > %d' % (offsets[-1][1], len(message))

    return message, offsets
