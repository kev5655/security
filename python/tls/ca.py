from fastapi import FastAPI
from settings import CA_PORT, SERVER_PORT
import uvicorn

app = FastAPI()

@app.get("/")
def root():
    return {"name": "ca"}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=CA_PORT)