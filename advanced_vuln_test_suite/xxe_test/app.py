
import xml.etree.ElementTree as ET
from flask import Flask, request

app = Flask(__name__)

# XXE VULNERABILITY: XML parsing with external entities enabled (default)
@app.route('/parse_xml', methods=['POST'])
def parse_xml():
    xml_data = request.data.decode('utf-8')
    # VULNERABLE: Default XML parser allows external entities
    try:
        root = ET.fromstring(xml_data)
        return f'Parsed: {root.tag}'
    except:
        return 'XML parsing error'

# XXE VULNERABILITY: Explicitly enabling external entities
@app.route('/parse_xml_vulnerable', methods=['POST'])
def parse_xml_vulnerable():
    xml_data = request.data.decode('utf-8')
    # VULNERABLE: Explicitly enabling dangerous features
    parser = ET.XMLParser()
    # Note: In real vulnerable code, this would enable external entities
    try:
        root = ET.fromstring(xml_data)
        return f'Parsed: {root.tag}'
    except:
        return 'XML parsing error'

# SAFE: Disabling external entities (conceptual)
@app.route('/parse_xml_safe', methods=['POST'])
def parse_xml_safe():
    xml_data = request.data.decode('utf-8')
    # SAFE: Using safe XML parsing (would need defusedxml in real code)
    try:
        # This is conceptual - real safe parsing would use defusedxml
        root = ET.fromstring(xml_data)
        return f'Safe parsed: {root.tag}'
    except:
        return 'Safe XML parsing error'

if __name__ == '__main__':
    app.run()
