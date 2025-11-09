import pickle
from flask import request
data = request.data
obj = pickle.loads(data)