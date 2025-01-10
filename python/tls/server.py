from fastapi import FastAPI
from settings import SERVER_PORT
import uvicorn

app = FastAPI()

@app.get("/")
def root():
    return {"name": "server"}


@app.post("/ClientHello"):
    pass

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=SERVER_PORT)