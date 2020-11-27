from .endpoint import Endpoint
from .exceptions import EndpointUnavailableError, ServerResponseError
from .. import RequestFactory
from ...models.tag_item import TagItem
import logging
import copy

# import urllib.parse
# Not using urllib.parse because unsupported by Python 2.7

logger = logging.getLogger('tableau.endpoint.resource_tagger')


class _ResourceTagger(Endpoint):
    # Add new tags to resource
    def _add_tags(self, baseurl, resource_id, tag_set):
        url = "{0}/{1}/tags".format(baseurl, resource_id)
        add_req = RequestFactory.Tag.add_req(tag_set)

        try:
            server_response = self.put_request(url, add_req)
            return TagItem.from_response(server_response.content, self.parent_srv.namespace)
        except ServerResponseError as e:
            if e.code == "404008":
                error = "Adding tags to this resource type is only available with REST API version 2.6 and later."
                raise EndpointUnavailableError(error)
            raise  # Some other error

    # Delete a resource's tag by name
    def _delete_tag(self, baseurl, resource_id, tag_name):
        encoded_tag_name = self._quote(tag_name)
        url = "{0}/{1}/tags/{2}".format(baseurl, resource_id, encoded_tag_name)

        try:
            self.delete_request(url)
        except ServerResponseError as e:
            if e.code == "404008":
                error = "Deleting tags from this resource type is only available with REST API version 2.6 and later."
                raise EndpointUnavailableError(error)
            raise  # Some other error

    def _quote(self, s, safe='/'):
        """quote('abc def') -> 'abc%20def'

        Each part of a URL, e.g. the path info, the query, etc., has a
        different set of reserved characters that must be quoted.

        RFC 2396 Uniform Resource Identifiers (URI): Generic Syntax lists
        the following reserved characters.

        reserved    = ";" | "/" | "?" | ":" | "@" | "&" | "=" | "+" |
                      "$" | ","

        Each of these characters is reserved in some component of a URL,
        but not necessarily in all of them.

        By default, the quote function is intended for quoting the path
        section of a URL.  Thus, it will not encode '/'.  This character
        is reserved, but in typical usage the quote function is being
        called on a path where the existing slash characters are used as
        reserved characters.
        """
        # fastpath
        if not s:
            if s is None:
                raise TypeError('None object cannot be quoted')
            return s
        cachekey = (safe, always_safe)
        try:
            (quoter, safe) = _safe_quoters[cachekey]
        except KeyError:
            safe_map = _safe_map.copy()
            safe_map.update([(c, c) for c in safe])
            quoter = safe_map.__getitem__
            safe = always_safe + safe
            _safe_quoters[cachekey] = (quoter, safe)
        if not s.rstrip(safe):
            return s
        return ''.join(map(quoter, s))

    # Remove and add tags to match the resource item's tag set
    def update_tags(self, baseurl, resource_item):
        if resource_item.tags != resource_item._initial_tags:
            add_set = resource_item.tags - resource_item._initial_tags
            remove_set = resource_item._initial_tags - resource_item.tags
            for tag in remove_set:
                self._delete_tag(baseurl, resource_item.id, tag)
            if add_set:
                resource_item.tags = self._add_tags(baseurl, resource_item.id, add_set)
            resource_item._initial_tags = copy.copy(resource_item.tags)
        logger.info('Updated tags to {0}'.format(resource_item.tags))
