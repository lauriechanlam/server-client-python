from .filter import Filter
from .sort import Sort

class RequestOptionsBase(object):
    def apply_query_params(self, url):
        raise NotImplementedError()


class RequestOptions(RequestOptionsBase):
    class Operator:
        Equals = 'eq'
        GreaterThan = 'gt'
        GreaterThanOrEqual = 'gte'
        LessThan = 'lt'
        LessThanOrEqual = 'lte'
        In = 'in'

    class Field:
        CreatedAt = 'createdAt'
        LastLogin = 'lastLogin'
        Name = 'name'
        OwnerName = 'ownerName'
        SiteRole = 'siteRole'
        Tags = 'tags'
        UpdatedAt = 'updatedAt'

    class Direction:
        Desc = 'desc'
        Asc = 'asc'

    class Builder:
        def __init__(self):
            self.__pagenumber = 1
            self.__pagesize = 100
            self.__filters = set()
            self.__sorts = set()

        def __getattr__(self, attr):
            def fn(*args, **kwargs):
                if (attr == '_sort'):
                    self.__sorts.add(Sort(args[0], args[1]))
                    return self
                elif (attr == '_pagenumber'):
                    self.__pagenumber = args[0]
                    return self
                elif (attr == '_pagesize'):
                    self.__pagesize = args[0]
                    return self
                elif (attr == '_build'):
                    ro = RequestOptions(self.__pagenumber, self.__pagesize)
                    ro.filter = self.__filters
                    ro.sort = self.__sorts
                    return ro
                else:
                    self.__filters.add(Filter(attr, Filter.Operator.map(args[0]), args[1]))
                    return self
            return fn


    def __init__(self, pagenumber=1, pagesize=100):
        self.pagenumber = pagenumber
        self.pagesize = pagesize
        self.sort = set()
        self.filter = set()

    def page_size(self, page_size):
        self.pagesize = page_size
        return self

    def page_number(self, page_number):
        self.pagenumber = page_number
        return self

    def apply_query_params(self, url):
        params = []
        if self.page_number:
            params.append('pageNumber={0}'.format(self.pagenumber))
        if self.page_size:
            params.append('pageSize={0}'.format(self.pagesize))
        if len(self.sort) > 0:
            sort_options = (str(sort_item) for sort_item in self.sort)
            ordered_sort_options = sorted(sort_options)
            params.append('sort={}'.format(','.join(ordered_sort_options)))
        if len(self.filter) > 0:
            filter_options = (str(filter_item) for filter_item in self.filter)
            ordered_filter_options = sorted(filter_options)
            params.append('filter={}'.format(','.join(ordered_filter_options)))

        return "{0}?{1}".format(url, '&'.join(params))


class ImageRequestOptions(RequestOptionsBase):
    # if 'high' isn't specified, the REST API endpoint returns an image with standard resolution
    class Resolution:
        High = 'high'

    def __init__(self, imageresolution=None):
        self.imageresolution = imageresolution

    def image_resolution(self, imageresolution):
        self.imageresolution = imageresolution
        return self

    def apply_query_params(self, url):
        params = []
        if self.image_resolution:
            params.append('resolution={0}'.format(self.imageresolution))

        return "{0}?{1}".format(url, '&'.join(params))


class ImageRequestOptions(RequestOptionsBase):
    # if 'high' isn't specified, the REST API endpoint returns an image with standard resolution
    class Resolution:
        High = 'high'

    def __init__(self, imageresolution=None):
        self.imageresolution = imageresolution

    def image_resolution(self, imageresolution):
        self.imageresolution = imageresolution
        return self

    def apply_query_params(self, url):
        params = []
        if self.image_resolution:
            params.append('resolution={0}'.format(self.imageresolution))

        return "{0}?{1}".format(url, '&'.join(params))
