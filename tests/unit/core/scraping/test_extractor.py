"""
Unit tests for DataExtractor and extraction utilities.

Tests structured data extraction from HTML elements using
schemas, tables, links, and images.
"""

from __future__ import annotations

import pytest
from bs4 import BeautifulSoup

from ciberwebscan.core.scraping.extractor import (
    DataExtractor,
    ExtractionSchema,
    FieldConfig,
    extract_images,
    extract_links,
    extract_structured,
    extract_table,
)


class TestFieldConfig:
    """Tests for FieldConfig dataclass."""

    def test_default_values(self):
        """Test default field configuration values."""
        config = FieldConfig()
        assert config.selector is None
        assert config.attr is None
        assert config.multiple is False
        assert config.default is None
        assert config.transform is None

    def test_custom_values(self):
        """Test custom field configuration."""
        config = FieldConfig(
            selector=".title",
            attr="href",
            multiple=True,
            default="N/A",
            transform="lower",
        )
        assert config.selector == ".title"
        assert config.attr == "href"
        assert config.multiple is True
        assert config.default == "N/A"
        assert config.transform == "lower"


class TestExtractionSchema:
    """Tests for ExtractionSchema dataclass."""

    def test_from_dict_simple(self):
        """Test creating schema from simple dict."""
        schema = ExtractionSchema.from_dict(
            {
                "title": {"selector": "h2"},
                "link": {"selector": "a", "attr": "href"},
            }
        )

        assert "title" in schema.fields
        assert schema.fields["title"].selector == "h2"
        assert schema.fields["link"].attr == "href"

    def test_from_dict_with_string_values(self):
        """Test creating schema with string shorthand."""
        schema = ExtractionSchema.from_dict(
            {
                "title": "h2.title",
                "content": "p.body",
            }
        )

        assert schema.fields["title"].selector == "h2.title"
        assert schema.fields["content"].selector == "p.body"

    def test_from_dict_all_options(self):
        """Test creating schema with all options."""
        schema = ExtractionSchema.from_dict(
            {
                "tags": {
                    "selector": ".tag",
                    "multiple": True,
                    "default": [],
                    "transform": "lower",
                },
            }
        )

        field = schema.fields["tags"]
        assert field.multiple is True
        assert field.default == []
        assert field.transform == "lower"


class TestDataExtractor:
    """Tests for DataExtractor class."""

    @pytest.fixture
    def extractor(self):
        """Create extractor instance."""
        return DataExtractor()

    @pytest.fixture
    def product_html(self):
        """Sample product HTML."""
        return """
        <div class="product">
            <h2 class="title">Test Product</h2>
            <span class="price">$19.99</span>
            <a href="/product/123" class="link">View</a>
            <div class="tags">
                <span class="tag">Electronics</span>
                <span class="tag">Sale</span>
            </div>
        </div>
        """

    def test_extract_text_field(self, extractor, product_html):
        """Test extracting text from element."""
        soup = BeautifulSoup(product_html, "html.parser")
        element = soup.select_one(".product")

        result = extractor.extract(
            element,
            {
                "title": {"selector": ".title"},
            },
        )

        assert result["title"] == "Test Product"

    def test_extract_attribute_field(self, extractor, product_html):
        """Test extracting attribute from element."""
        soup = BeautifulSoup(product_html, "html.parser")
        element = soup.select_one(".product")

        result = extractor.extract(
            element,
            {
                "url": {"selector": ".link", "attr": "href"},
            },
        )

        assert result["url"] == "/product/123"

    def test_extract_multiple_values(self, extractor, product_html):
        """Test extracting multiple values."""
        soup = BeautifulSoup(product_html, "html.parser")
        element = soup.select_one(".product")

        result = extractor.extract(
            element,
            {
                "tags": {"selector": ".tag", "multiple": True},
            },
        )

        assert result["tags"] == ["Electronics", "Sale"]

    def test_extract_with_default(self, extractor, product_html):
        """Test default value for missing field."""
        soup = BeautifulSoup(product_html, "html.parser")
        element = soup.select_one(".product")

        result = extractor.extract(
            element,
            {
                "rating": {"selector": ".rating", "default": "N/A"},
            },
        )

        assert result["rating"] == "N/A"

    def test_extract_with_transform_lower(self, extractor, product_html):
        """Test lowercase transform."""
        soup = BeautifulSoup(product_html, "html.parser")
        element = soup.select_one(".product")

        result = extractor.extract(
            element,
            {
                "title": {"selector": ".title", "transform": "lower"},
            },
        )

        assert result["title"] == "test product"

    def test_extract_with_transform_upper(self, extractor, product_html):
        """Test uppercase transform."""
        soup = BeautifulSoup(product_html, "html.parser")
        element = soup.select_one(".product")

        result = extractor.extract(
            element,
            {
                "title": {"selector": ".title", "transform": "upper"},
            },
        )

        assert result["title"] == "TEST PRODUCT"

    def test_extract_many(self, extractor):
        """Test extracting from multiple elements."""
        html = """
        <div id="products">
            <div class="item"><span class="name">Item 1</span></div>
            <div class="item"><span class="name">Item 2</span></div>
            <div class="item"><span class="name">Item 3</span></div>
        </div>
        """
        soup = BeautifulSoup(html, "html.parser")

        result = extractor.extract_many(
            soup,
            ".item",
            {
                "name": {"selector": ".name"},
            },
        )

        assert len(result) == 3
        assert result[0]["name"] == "Item 1"
        assert result[2]["name"] == "Item 3"

    def test_extract_with_schema_object(self, extractor, product_html):
        """Test extraction with ExtractionSchema object."""
        soup = BeautifulSoup(product_html, "html.parser")
        element = soup.select_one(".product")

        schema = ExtractionSchema.from_dict(
            {
                "title": {"selector": ".title"},
                "price": {"selector": ".price"},
            }
        )

        result = extractor.extract(element, schema)

        assert result["title"] == "Test Product"
        assert result["price"] == "$19.99"

    def test_extract_without_selector(self, extractor):
        """Test extracting text from element itself."""
        html = "<span>Direct Text</span>"
        soup = BeautifulSoup(html, "html.parser")
        element = soup.span

        result = extractor.extract(
            element,
            {
                "text": {},  # No selector means extract from element
            },
        )

        assert result["text"] == "Direct Text"

    def test_extract_attr_without_selector(self, extractor):
        """Test extracting attribute from element itself."""
        html = '<a href="/link" class="btn">Click</a>'
        soup = BeautifulSoup(html, "html.parser")
        element = soup.a

        result = extractor.extract(
            element,
            {
                "url": {"attr": "href"},
            },
        )

        assert result["url"] == "/link"


class TestExtractStructured:
    """Tests for extract_structured convenience function."""

    def test_basic_extraction(self):
        """Test basic structured extraction."""
        html = "<div><h1>Title</h1><p>Content</p></div>"
        soup = BeautifulSoup(html, "html.parser")
        element = soup.div
        assert element is not None

        result = extract_structured(
            element,
            {
                "heading": {"selector": "h1"},
                "body": {"selector": "p"},
            },
        )

        assert result["heading"] == "Title"
        assert result["body"] == "Content"


class TestExtractTable:
    """Tests for extract_table function."""

    def test_simple_table(self):
        """Test extracting simple table."""
        html = """
        <table>
            <tr><th>Name</th><th>Age</th></tr>
            <tr><td>Alice</td><td>30</td></tr>
            <tr><td>Bob</td><td>25</td></tr>
        </table>
        """
        soup = BeautifulSoup(html, "html.parser")
        table = soup.table
        assert table is not None

        result = extract_table(table)

        assert len(result) == 2
        assert result[0]["Name"] == "Alice"
        assert result[0]["Age"] == "30"
        assert result[1]["Name"] == "Bob"

    def test_table_with_thead(self):
        """Test table with thead and tbody."""
        html = """
        <table>
            <thead><tr><th>Product</th><th>Price</th></tr></thead>
            <tbody>
                <tr><td>Widget</td><td>$10</td></tr>
                <tr><td>Gadget</td><td>$20</td></tr>
            </tbody>
        </table>
        """
        soup = BeautifulSoup(html, "html.parser")
        table = soup.table
        assert table is not None

        result = extract_table(table)

        assert len(result) == 2
        assert result[0]["Product"] == "Widget"
        assert result[1]["Price"] == "$20"

    def test_table_skip_rows(self):
        """Test skipping rows after header."""
        html = """
        <table>
            <tr><th>Col1</th><th>Col2</th></tr>
            <tr><td colspan="2">Subtitle row</td></tr>
            <tr><td>Data1</td><td>Data2</td></tr>
        </table>
        """
        soup = BeautifulSoup(html, "html.parser")
        table = soup.table
        assert table is not None
        result = extract_table(table, skip_rows=1)

        assert len(result) == 1
        assert result[0]["Col1"] == "Data1"

    def test_empty_table(self):
        """Test empty table."""
        html = "<table></table>"
        soup = BeautifulSoup(html, "html.parser")
        table = soup.table
        assert table is not None

        result = extract_table(table)

        assert result == []


class TestExtractLinks:
    """Tests for extract_links function."""

    def test_basic_links(self):
        """Test extracting basic links."""
        html = """
        <div>
            <a href="/page1">Page 1</a>
            <a href="/page2">Page 2</a>
        </div>
        """
        soup = BeautifulSoup(html, "html.parser")

        result = extract_links(soup)

        assert len(result) == 2
        assert result[0]["href"] == "/page1"
        assert result[0]["text"] == "Page 1"

    def test_links_with_base_url(self):
        """Test resolving relative URLs."""
        html = '<a href="/path">Link</a>'
        soup = BeautifulSoup(html, "html.parser")

        result = extract_links(soup, base_url="https://example.com")

        assert result[0]["href"] == "https://example.com/path"

    def test_absolute_links_preserved(self):
        """Test absolute URLs are not modified."""
        html = '<a href="https://other.com/page">Link</a>'
        soup = BeautifulSoup(html, "html.parser")

        result = extract_links(soup, base_url="https://example.com")

        assert result[0]["href"] == "https://other.com/page"

    def test_links_without_text(self):
        """Test extracting links without text."""
        html = '<a href="/page">Link</a>'
        soup = BeautifulSoup(html, "html.parser")

        result = extract_links(soup, include_text=False)

        assert "text" not in result[0]

    def test_custom_selector(self):
        """Test custom link selector."""
        html = """
        <nav><a href="/nav" class="nav-link">Nav</a></nav>
        <div><a href="/content">Content</a></div>
        """
        soup = BeautifulSoup(html, "html.parser")

        result = extract_links(soup, selector="nav a")

        assert len(result) == 1
        assert result[0]["href"] == "/nav"

    def test_skip_empty_href(self):
        """Test skipping links without href."""
        html = '<a>No href</a><a href="">Empty</a><a href="/valid">Valid</a>'
        soup = BeautifulSoup(html, "html.parser")

        result = extract_links(soup)

        assert len(result) == 1
        assert result[0]["href"] == "/valid"


class TestExtractImages:
    """Tests for extract_images function."""

    def test_basic_images(self):
        """Test extracting basic images."""
        html = """
        <div>
            <img src="/img1.jpg" alt="Image 1">
            <img src="/img2.png" alt="Image 2">
        </div>
        """
        soup = BeautifulSoup(html, "html.parser")

        result = extract_images(soup)

        assert len(result) == 2
        assert result[0]["src"] == "/img1.jpg"
        assert result[0]["alt"] == "Image 1"

    def test_images_with_base_url(self):
        """Test resolving relative image URLs."""
        html = '<img src="/images/photo.jpg" alt="Photo">'
        soup = BeautifulSoup(html, "html.parser")

        result = extract_images(soup, base_url="https://example.com")

        assert result[0]["src"] == "https://example.com/images/photo.jpg"

    def test_data_uri_preserved(self):
        """Test data URIs are not modified."""
        html = '<img src="data:image/png;base64,ABC123" alt="Inline">'
        soup = BeautifulSoup(html, "html.parser")

        result = extract_images(soup, base_url="https://example.com")

        assert result[0]["src"].startswith("data:")

    def test_image_additional_attrs(self):
        """Test extracting additional image attributes."""
        html = '<img src="/img.jpg" alt="Test" title="Title" width="100" height="50">'
        soup = BeautifulSoup(html, "html.parser")

        result = extract_images(soup)

        assert result[0]["title"] == "Title"
        assert result[0]["width"] == "100"
        assert result[0]["height"] == "50"

    def test_skip_images_without_src(self):
        """Test skipping images without src."""
        html = '<img alt="No src"><img src="/valid.jpg" alt="Valid">'
        soup = BeautifulSoup(html, "html.parser")

        result = extract_images(soup)

        assert len(result) == 1
        assert result[0]["src"] == "/valid.jpg"

    def test_custom_image_selector(self):
        """Test custom image selector."""
        html = """
        <div class="gallery"><img src="/gallery.jpg" alt="Gallery"></div>
        <div class="thumb"><img src="/thumb.jpg" alt="Thumb"></div>
        """
        soup = BeautifulSoup(html, "html.parser")

        result = extract_images(soup, selector=".gallery img")

        assert len(result) == 1
        assert result[0]["alt"] == "Gallery"


class TestTransformations:
    """Tests for value transformations."""

    @pytest.fixture
    def extractor(self):
        """Create extractor instance."""
        return DataExtractor()

    def test_strip_transform(self, extractor):
        """Test strip transformation."""
        html = "<span>  padded  </span>"
        soup = BeautifulSoup(html, "html.parser")

        result = extractor.extract(
            soup.span,
            {
                "text": {"transform": "strip"},
            },
        )

        assert result["text"] == "padded"

    def test_int_transform(self, extractor):
        """Test integer transformation."""
        html = "<span>42</span>"
        soup = BeautifulSoup(html, "html.parser")

        result = extractor.extract(
            soup.span,
            {
                "number": {"transform": "int"},
            },
        )

        assert result["number"] == 42
        assert isinstance(result["number"], int)

    def test_float_transform(self, extractor):
        """Test float transformation."""
        html = "<span>19,99</span>"
        soup = BeautifulSoup(html, "html.parser")

        result = extractor.extract(
            soup.span,
            {
                "price": {"transform": "float"},
            },
        )

        assert result["price"] == 19.99
        assert isinstance(result["price"], float)

    def test_transform_error_returns_original(self, extractor):
        """Test transform error returns original value."""
        html = "<span>not-a-number</span>"
        soup = BeautifulSoup(html, "html.parser")

        result = extractor.extract(
            soup.span,
            {
                "value": {"transform": "int"},
            },
        )

        # Should return original value on transform error
        assert result["value"] == "not-a-number"

    def test_multiple_with_transform(self, extractor):
        """Test multiple values with transform."""
        html = """
        <div>
            <span class="num">10</span>
            <span class="num">20</span>
            <span class="num">30</span>
        </div>
        """
        soup = BeautifulSoup(html, "html.parser")

        result = extractor.extract(
            soup.div,
            {
                "numbers": {"selector": ".num", "multiple": True, "transform": "int"},
            },
        )

        assert result["numbers"] == [10, 20, 30]
