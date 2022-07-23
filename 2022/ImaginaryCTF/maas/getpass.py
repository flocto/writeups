from hashlib import sha256
import uuid
import random

users = {}
taken = []
def adduser(username):
  if username in taken:
    return "username taken", "username taken"
  password = "".join([random.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(30)])
  cookie = sha256(password.encode()).hexdigest()
  users[cookie] = {"username": username, "id": str(uuid.uuid1())}
  taken.append(username)
  return cookie, password

random.seed(1658556457.49)
print(adduser("admin"))