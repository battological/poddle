from xml.dom import getDOMImplementation

TEXT_ATTRIBUTE = '_text'


class RSSElement(object):
    def __init__(self, name, text=None, **attributes):
        self.name = name
        self.text = text
        self.attributes = attributes


class RSSWriter(object):
    def __init__(self, title, link, description, **optionals):
        """
        :param title: Channel title.
        :param link: Channel link URL. Should be a URL beginning with http://...
        :param description: Channel description.
        :param optionals: Optional channel elements. Keyword args of form element_name=element_text or
                          element_name={attribute_name: attribute_value, ..., ['_text': element_text]}
        """
        self._xml = getDOMImplementation().createDocument(None, None, None)
        rss = self._append_new(self._xml, RSSElement('rss',
                                                     version='2.0',
                                                     **{'xmlns:itunes': 'http://www.itunes.com/dtds/podcast-1.0.dtd'}))

        self._channel = self._append_new(rss, RSSElement('channel'))

        # Add required elements
        self._append_new(self._channel, RSSElement('title', title))
        self._append_new(self._channel, RSSElement('description', description))
        self._append_new(self._channel, RSSElement('link', link))

        # Add optional elements
        for optional in optionals:
            self._append_new(self._channel, self._optional_element(optional, optionals[optional]))

    def __str__(self):
        return self._xml.toxml('utf-8')

    def add_to_channel(self, name, text=None, **attributes):
        self._append_new(self._channel, RSSElement(name, text, **attributes))

    def add_item(self, title=None, description=None, **optionals):
        """
        Item element to be inserted into channel. At least one of title or description must be present.
        :param title: The title of the item.
        :param description: The item synopsis.
        """
        if not title and not description:
            raise InvalidElementError('Invalid item. Must provide at least one of title or description.')

        item = self._append_new(self._channel, RSSElement('item'))

        if title:
            self._append_new(item, RSSElement('title', title))
        if description:
            self._append_new(item, RSSElement('description', description))

        for optional in optionals:
            self._append_new(item, self._optional_element(optional, optionals[optional]))

    def _append_new(self, parent, new_element):
        ne = self._xml.createElement(new_element.name)
        for attribute in new_element.attributes:
            ne.setAttribute(attribute, new_element.attributes[attribute])
        if new_element.text:
            text = self._xml.createTextNode(new_element.text)
            ne.appendChild(text)
        parent.appendChild(ne)
        return ne

    @staticmethod
    def _optional_element(element_name, value):
        if isinstance(value, dict):  # if value is a dict (i.e. a dict of {attr_name: attr_value})
            return RSSElement(element_name, value.pop(TEXT_ATTRIBUTE, None), **value)
        return RSSElement(element_name, value)  # if value is just the element text


class InvalidElementError(Exception):
    pass
