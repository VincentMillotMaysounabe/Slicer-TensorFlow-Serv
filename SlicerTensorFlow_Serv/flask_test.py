from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def great():
    return {"message": "Bonjour !"}
@app.post("/envoyer")
def send():
    return {"message": "ce message vient du serveur"}