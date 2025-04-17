from fastapi import FastAPI
from pymongo import MongoClient
from bson.objectid import ObjectId

app = FastAPI()

client = MongoClient("mongodb://database:27017/")
db = client.hercules
people = db.people

people.delete_many({})

@app.get("/")
def index():
  all_people = list(people.find({}, {"_id": 0}))
  return {'people': all_people}

@app.get("/{name}")
def another_human(name):
  human_id = people.insert_one({"name": name}).inserted_id
  return {"human_id": people.find({"_id": ObjectId(human_id)})}