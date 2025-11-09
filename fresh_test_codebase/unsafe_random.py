import random
def generate_token():
    # CWE-330: Use of Insufficiently Random Values
    return str(random.randint(1000, 9999))