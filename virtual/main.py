from fastapi import FastAPI
from virtual.models import models
from virtual.controller import user_controller

from virtual.db import database

models.database.Base.metadata.create_all(bind=database.engine)


app = FastAPI()

app.include_router(user_controller.router)
