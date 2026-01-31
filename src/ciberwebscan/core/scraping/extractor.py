"""
Structured data extraction from HTML.

Provides schema-based extraction of structured data from BeautifulSoup elements,
supporting nested selectors, multiple values, and default fallbacks.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from bs4 import BeautifulSoup
from bs4.element import Tag

logger = logging.getLogger(__name__)


@dataclass
class FieldConfig:
    """Configuration for a single field extraction."""

    selector: str | None = None
    attr: str | None = None
    multiple: bool = False
    default: Any = None
    transform: str | None = None  # 'lower', 'upper', 'strip', 'int', 'float'


@dataclass
class ExtractionSchema:
    """
    Schema for structured data extraction.

    Defines how to extract multiple fields from an HTML element.

    Examples:
        >>> schema = ExtractionSchema(fields={
        ...     'title': FieldConfig(selector='h2.title'),
        ...     'price': FieldConfig(selector='.price', transform='float'),
        ...     'tags': FieldConfig(selector='.tag', multiple=True),
        ...     'url': FieldConfig(selector='a', attr='href'),
        ... })
    """

    fields: dict[str, FieldConfig] = field(default_factory=dict)
    root_selector: str | None = None

    @classmethod
    def from_dict(cls, schema_dict: dict[str, Any]) -> "ExtractionSchema":
        """
        Create schema from dictionary.

        Args:
            schema_dict: Dictionary with field configurations.

        Returns:
            ExtractionSchema instance.

        Examples:
            >>> schema = ExtractionSchema.from_dict({
            ...     'title': {'selector': 'h2'},
            ...     'link': {'selector': 'a', 'attr': 'href'},
            ... })
        """
        fields = {}
        for name, config in schema_dict.items():
            if isinstance(config, dict):
                fields[name] = FieldConfig(
                    selector=config.get("selector"),
                    attr=config.get("attr"),
                    multiple=config.get("multiple", False),
                    default=config.get("default"),
                    transform=config.get("transform"),
                )
            else:
                # Simple string selector
                fields[name] = FieldConfig(selector=str(config))

        return cls(fields=fields)


class DataExtractor:
    """
    Extract structured data from HTML elements using schemas.

    This class provides flexible extraction of data from HTML using
    CSS selectors, attribute extraction, and value transformations.

    Examples:
        >>> extractor = DataExtractor()
        >>> schema = {'title': {'selector': 'h2'}, 'link': {'selector': 'a', 'attr': 'href'}}
        >>> html = '<div><h2>Hello</h2><a href="/page">Link</a></div>'
        >>> soup = BeautifulSoup(html, 'html.parser')
        >>> result = extractor.extract(soup.div, schema)
        >>> result
        {'title': 'Hello', 'link': '/page'}
    """

    def __init__(self) -> None:
        """Initialize the data extractor."""
        self._transforms = {
            "lower": lambda x: x.lower() if isinstance(x, str) else x,
            "upper": lambda x: x.upper() if isinstance(x, str) else x,
            "strip": lambda x: x.strip() if isinstance(x, str) else x,
            "int": lambda x: int(x) if x else None,
            "float": lambda x: float(x.replace(",", ".")) if x else None,
        }

    def extract(
        self,
        element: Tag,
        schema: dict[str, Any] | ExtractionSchema,
    ) -> dict[str, Any]:
        """
        Extract data from element using schema.

        Args:
            element: BeautifulSoup Tag element.
            schema: Extraction schema (dict or ExtractionSchema).

        Returns:
            Dictionary of extracted field values.

        Examples:
            >>> extractor = DataExtractor()
            >>> schema = {
            ...     'text': {'selector': 'span.content'},
            ...     'author': {'selector': '.author'},
            ...     'tags': {'selector': '.tag', 'multiple': True},
            ... }
            >>> result = extractor.extract(element, schema)
        """
        if isinstance(schema, dict):
            schema = ExtractionSchema.from_dict(schema)

        result: dict[str, Any] = {}

        for field_name, config in schema.fields.items():
            value = self._extract_field(element, config)
            if value is not None or config.default is not None:
                result[field_name] = value if value is not None else config.default

        return result

    def extract_many(
        self,
        soup: BeautifulSoup,
        item_selector: str,
        schema: dict[str, Any] | ExtractionSchema,
    ) -> list[dict[str, Any]]:
        """
        Extract data from multiple elements.

        Args:
            soup: BeautifulSoup object.
            item_selector: CSS selector for items to extract.
            schema: Extraction schema for each item.

        Returns:
            List of extracted data dictionaries.

        Examples:
            >>> extractor = DataExtractor()
            >>> items = extractor.extract_many(soup, 'div.product', {
            ...     'name': {'selector': '.name'},
            ...     'price': {'selector': '.price'},
            ... })
        """
        elements = soup.select(item_selector)
        return [self.extract(el, schema) for el in elements]

    def _extract_field(self, element: Tag, config: FieldConfig) -> Any:
        """Extract a single field value from element."""
        if config.selector:
            return self._extract_by_selector(element, config)
        elif config.attr:
            # Extract attribute from the element itself
            value = element.get(config.attr, config.default)
            return self._apply_transform(value, config.transform)
        else:
            # Extract text from the element itself
            value = element.get_text(strip=True)
            return self._apply_transform(value, config.transform)

    def _extract_by_selector(self, element: Tag, config: FieldConfig) -> Any:
        """Extract value using CSS selector."""
        assert config.selector is not None  # Caller ensures this
        
        if config.multiple:
            # Extract multiple values
            elements = element.select(config.selector)
            if config.attr:
                values = [el.get(config.attr) for el in elements if el.get(config.attr)]
            else:
                values = [el.get_text(strip=True) for el in elements]

            # Apply transform to each value
            if config.transform:
                values = [self._apply_transform(v, config.transform) for v in values]

            return values if values else config.default
        else:
            # Extract single value
            found = element.select_one(config.selector)
            if not found:
                return config.default

            if config.attr:
                value = found.get(config.attr, config.default)
            else:
                value = found.get_text(strip=True)

            return self._apply_transform(value, config.transform)

    def _apply_transform(self, value: Any, transform: str | None) -> Any:
        """Apply transformation to value."""
        if not transform or value is None:
            return value

        transform_func = self._transforms.get(transform)
        if transform_func:
            try:
                return transform_func(value)
            except (ValueError, TypeError, AttributeError):
                return value

        return value


def extract_structured(element: Tag, schema: dict[str, Any]) -> dict[str, Any]:
    """
    Convenience function for structured extraction.

    Args:
        element: BeautifulSoup Tag element.
        schema: Extraction schema dictionary.

    Returns:
        Extracted data dictionary.

    Examples:
        >>> schema = {
        ...     'quote': {'selector': 'span.text'},
        ...     'author': {'selector': 'small.author'},
        ...     'tags': {'selector': '.tag', 'multiple': True},
        ... }
        >>> data = extract_structured(quote_element, schema)
    """
    extractor = DataExtractor()
    return extractor.extract(element, schema)


def extract_table(
    table: Tag,
    *,
    header_row: int = 0,
    skip_rows: int = 0,
) -> list[dict[str, str]]:
    """
    Extract data from HTML table as list of dictionaries.

    Args:
        table: BeautifulSoup table element.
        header_row: Row index for headers (default 0).
        skip_rows: Number of data rows to skip after header.

    Returns:
        List of dictionaries with column headers as keys.

    Examples:
        >>> table = soup.select_one('table')
        >>> data = extract_table(table)
        >>> data[0]['Column1']
        'Value1'
    """
    rows = table.select("tr")
    if not rows:
        return []

    # Extract headers
    header_cells = rows[header_row].select("th, td")
    headers = [cell.get_text(strip=True) for cell in header_cells]

    # Extract data rows
    data = []
    start_row = header_row + 1 + skip_rows

    for row in rows[start_row:]:
        cells = row.select("td")
        if not cells:
            continue

        row_data = {}
        for i, cell in enumerate(cells):
            if i < len(headers):
                row_data[headers[i]] = cell.get_text(strip=True)
            else:
                row_data[f"column_{i}"] = cell.get_text(strip=True)

        if row_data:
            data.append(row_data)

    return data


def extract_links(
    soup: BeautifulSoup,
    *,
    base_url: str | None = None,
    selector: str = "a[href]",
    include_text: bool = True,
) -> list[dict[str, str]]:
    """
    Extract all links from HTML.

    Args:
        soup: BeautifulSoup object.
        base_url: Base URL for resolving relative links.
        selector: CSS selector for link elements.
        include_text: Whether to include link text.

    Returns:
        List of link dictionaries with 'href' and optionally 'text'.

    Examples:
        >>> links = extract_links(soup, base_url='https://example.com')
        >>> links[0]
        {'href': 'https://example.com/page', 'text': 'Page Link'}
    """
    from urllib.parse import urljoin

    links = []

    for anchor in soup.select(selector):
        href = anchor.get("href")
        if not href or not isinstance(href, str):
            continue

        # Resolve relative URLs
        if base_url and not href.startswith(("http://", "https://", "mailto:", "tel:")):
            href = urljoin(base_url, href)

        link_data = {"href": href}

        if include_text:
            link_data["text"] = anchor.get_text(strip=True)

        links.append(link_data)

    return links


def extract_images(
    soup: BeautifulSoup,
    *,
    base_url: str | None = None,
    selector: str = "img[src]",
) -> list[dict[str, str]]:
    """
    Extract all images from HTML.

    Args:
        soup: BeautifulSoup object.
        base_url: Base URL for resolving relative sources.
        selector: CSS selector for image elements.

    Returns:
        List of image dictionaries with 'src', 'alt', etc.

    Examples:
        >>> images = extract_images(soup)
        >>> images[0]
        {'src': 'https://example.com/img.jpg', 'alt': 'Description'}
    """
    from urllib.parse import urljoin

    images = []

    for img in soup.select(selector):
        src = img.get("src")
        if not src or not isinstance(src, str):
            continue

        # Resolve relative URLs
        if base_url and not src.startswith(("http://", "https://", "data:")):
            src = urljoin(base_url, src)

        image_data = {
            "src": src,
            "alt": img.get("alt", ""),
        }

        # Include additional attributes if present
        for attr in ["title", "width", "height", "loading"]:
            if img.get(attr):
                image_data[attr] = img.get(attr)

        images.append(image_data)

    return images
