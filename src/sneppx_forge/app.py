from fastapi import FastAPI

from sneppx_forge.api import create_app as _create_app

app = _create_app()


def create_app():
    return app
