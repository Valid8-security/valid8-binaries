import pickle
def load_user_data(data):
    # CWE-502: Unsafe Deserialization
    return pickle.loads(data)  # Never do this