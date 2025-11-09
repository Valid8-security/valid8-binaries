import pickle

def save_session(session_data):
    # CWE-502: Unsafe Serialization
    with open('session.pkl', 'wb') as f:
        pickle.dump(session_data, f)  # Unsafe pickle

def load_session():
    # CWE-502: Unsafe Deserialization
    with open('session.pkl', 'rb') as f:
        return pickle.load(f)  # Unsafe unpickle
