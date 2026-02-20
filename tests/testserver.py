"""
Simple test server for integration testing.

Provides vulnerable endpoints for testing attack simulations.
WARNING: Only for testing purposes! Never deploy this in production!
"""

from __future__ import annotations

import logging

import pytest
from fastapi import FastAPI, Form, Query
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

# when running under a bare CLI installation the API packages may not be
# available; tests that depend on this server should skip themselves
# instead of crashing during import. pytest.importorskip will raise a
# Skip exception but evaluating it here would skip import of the whole
# module which is fine because nothing else uses it without checking.
pytest.importorskip("fastapi")
pytest.importorskip("python_multipart")


# Disable uvicorn logging in tests
log = logging.getLogger("uvicorn")
log.setLevel(logging.ERROR)

app = FastAPI(title="Test Server", docs_url=None, redoc_url=None)


# ============================================================================
# XSS Vulnerable Endpoints
# ============================================================================


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    """Home page."""
    return """
    <html>
        <head><title>Test Site</title></head>
        <body>
            <h1>Vulnerable Test Site</h1>
            <p>For testing purposes only!</p>
            <ul>
                <li><a href="/xss?q=test">XSS Test</a></li>
                <li><a href="/search?query=test">Search (SQLi)</a></li>
                <li><a href="/file?path=test.txt">File Access (Traversal)</a></li>
                <li><a href="/api/admin">Admin API</a></li>
            </ul>
        </body>
    </html>
    """


@app.get("/xss", response_class=HTMLResponse)
def xss_vulnerable(q: str = Query(default="")) -> str:
    """Vulnerable to reflected XSS."""
    # INTENTIONALLY VULNERABLE: No escaping!
    return f"""
    <html>
        <head><title>Search Results</title></head>
        <body>
            <h1>Search Results</h1>
            <p>You searched for: {q}</p>
        </body>
    </html>
    """


@app.get("/search", response_class=HTMLResponse)
def search_vulnerable(query: str = Query(default="")) -> str:
    """Vulnerable to reflected XSS in search."""
    # INTENTIONALLY VULNERABLE
    return f"""
    <html>
        <body>
            <h1>Results for: {query}</h1>
        </body>
    </html>
    """


# ============================================================================
# SQLi Vulnerable Endpoints
# ============================================================================


@app.get("/user")
def user_profile(id: str = Query(default="1")) -> JSONResponse:
    """Vulnerable to SQL injection (simulated)."""
    # Simulate SQL injection vulnerability
    # Check for common SQLi patterns
    sqli_patterns = [
        "'",
        '"',
        " OR ",
        " AND ",
        "1=1",
        "UNION",
        "SELECT",
        "--",
        "/*",
        "xp_",
    ]

    is_vulnerable = any(pattern.upper() in id.upper() for pattern in sqli_patterns)

    if is_vulnerable:
        # Simulate SQL error
        return JSONResponse(
            {
                "error": "Database error",
                "details": "You have an error in your SQL syntax",
                "query": f"SELECT * FROM users WHERE id = {id}",
            },
            status_code=500,
        )

    return JSONResponse({"id": id, "name": "Test User", "email": "test@example.com"})


@app.get("/login", response_class=HTMLResponse)
def login_form() -> str:
    """Login form."""
    return """
    <html>
        <body>
            <form method="post" action="/login">
                <input name="username" placeholder="Username">
                <input name="password" type="password" placeholder="Password">
                <button type="submit">Login</button>
            </form>
        </body>
    </html>
    """


@app.post("/login")
def login_vulnerable(
    username: str = Form(default=""), password: str = Form(default="")
) -> JSONResponse:
    """Vulnerable login endpoint."""
    # Check for SQLi patterns
    sqli_patterns = ["' OR", "' or", "1=1", "admin'--", "' --"]
    is_sqli = any(
        pattern in username or pattern in password for pattern in sqli_patterns
    )

    if is_sqli:
        return JSONResponse(
            {
                "error": "SQL syntax error",
                "query": f"SELECT * FROM users WHERE username='{username}' AND password='{password}'",
            },
            status_code=500,
        )

    return JSONResponse({"status": "failed", "message": "Invalid credentials"})


# ============================================================================
# Path Traversal Vulnerable Endpoints
# ============================================================================


@app.get("/file")
def read_file(path: str = Query(default="")) -> JSONResponse:
    """Vulnerable to path traversal."""
    # Simulate path traversal vulnerability
    traversal_patterns = ["../", "..\\", "/etc/", "c:\\", "\\windows\\"]

    is_vulnerable = any(pattern in path.lower() for pattern in traversal_patterns)

    if is_vulnerable:
        return JSONResponse(
            {
                "error": "File access error",
                "path": path,
                "details": f"Attempting to access: {path}",
            },
            status_code=500,
        )

    return JSONResponse({"content": "File content here", "path": path})


@app.get("/download")
def download(file: str = Query(default="")) -> JSONResponse:
    """Another path traversal endpoint."""
    if "../" in file or "..\\" in file:
        return JSONResponse(
            {
                "error": "Invalid file path",
                "attempted_path": file,
            },
            status_code=403,
        )

    return JSONResponse({"file": file, "size": 1024})


# ============================================================================
# Directory Enumeration Endpoints
# ============================================================================


@app.get("/api/users")
def api_users() -> JSONResponse:
    """Public API endpoint."""
    return JSONResponse(
        {"users": [{"id": 1, "name": "John"}, {"id": 2, "name": "Jane"}]}
    )


@app.get("/api/admin")
def api_admin() -> JSONResponse:
    """Should be protected but isn't."""
    return JSONResponse(
        {"secret": "admin_data", "message": "You found the admin endpoint!"}
    )


@app.get("/api/config")
def api_config() -> JSONResponse:
    """Exposed configuration endpoint."""
    return JSONResponse(
        {
            "database": "mysql://localhost",
            "api_key": "secret_key_12345",
            "debug": True,
        }
    )


@app.get("/backup")
def backup_files() -> JSONResponse:
    """Exposed backup directory."""
    return JSONResponse({"files": ["backup.sql", "db_dump.sql", "config.bak"]})


@app.get("/.env", response_class=PlainTextResponse)
def env_file() -> str:
    """Exposed .env file."""
    return "DB_PASSWORD=secret123\nAPI_KEY=xyz789\n"


@app.get("/robots.txt", response_class=PlainTextResponse)
def robots() -> str:
    """Robots.txt with hints."""
    return """User-agent: *
Disallow: /admin
Disallow: /backup
Disallow: /.env
Disallow: /api/config
"""


# ============================================================================
# Additional endpoints
# ============================================================================


@app.get("/admin", response_class=HTMLResponse)
def admin_panel() -> str:
    """Admin panel."""
    return "<html><body><h1>Admin Panel</h1></body></html>"


@app.get("/status")
def status() -> JSONResponse:
    """Health check endpoint."""
    return JSONResponse({"status": "ok", "version": "1.0.0"})


def create_app() -> FastAPI:
    """Create and configure the FastAPI app."""
    return app


if __name__ == "__main__":
    import uvicorn

    print("Starting vulnerable test server on http://127.0.0.1:5555")
    print("WARNING: This server is intentionally vulnerable!")
    print("Only use for testing purposes!")
    uvicorn.run(app, host="127.0.0.1", port=5555, log_level="error")
