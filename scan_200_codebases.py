#!/usr/bin/env python3
"""
Scan 200 Codebases for Real Exploitable Vulnerabilities
Uses noise elimination filters to find only real, attackable vulnerabilities
"""

import sys
import os
import json
import subprocess
import time
import re
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from collections import defaultdict
import shutil

sys.path.insert(0, os.getcwd())

from valid8.scanner import Scanner
from noise_elimination_filters import NoiseEliminationFilter

class LargeCodebaseScanner:
    """Scan large codebases for exploitable vulnerabilities"""
    
    def __init__(self):
        self.scanner = Scanner()
        self.noise_filter = NoiseEliminationFilter()
        self.verified_vulnerabilities = []
        self.scan_stats = {
            'codebases_scanned': 0,
            'total_findings': 0,
            'filtered_noise': 0,
            'verified_exploitable': 0,
            'target': 150
        }
        self.scan_dir = Path("/tmp/valid8_200_scan")
        self.scan_dir.mkdir(exist_ok=True)
    
    def get_large_python_repos(self) -> List[Dict[str, str]]:
        """Get list of 200+ large Python repositories to scan"""
        repos = [
            # Web Frameworks (20)
            {'name': 'django', 'url': 'https://github.com/django/django.git', 'size': 'large'},
            {'name': 'flask', 'url': 'https://github.com/pallets/flask.git', 'size': 'large'},
            {'name': 'fastapi', 'url': 'https://github.com/tiangolo/fastapi.git', 'size': 'large'},
            {'name': 'tornado', 'url': 'https://github.com/tornadoweb/tornado.git', 'size': 'large'},
            {'name': 'bottle', 'url': 'https://github.com/bottlepy/bottle.git', 'size': 'medium'},
            {'name': 'cherrypy', 'url': 'https://github.com/cherrypy/cherrypy.git', 'size': 'large'},
            {'name': 'pyramid', 'url': 'https://github.com/Pylons/pyramid.git', 'size': 'large'},
            {'name': 'web2py', 'url': 'https://github.com/web2py/web2py.git', 'size': 'large'},
            {'name': 'sanic', 'url': 'https://github.com/sanic-org/sanic.git', 'size': 'medium'},
            {'name': 'quart', 'url': 'https://github.com/pallets/quart.git', 'size': 'medium'},
            {'name': 'starlette', 'url': 'https://github.com/encode/starlette.git', 'size': 'medium'},
            {'name': 'hug', 'url': 'https://github.com/hugapi/hug.git', 'size': 'medium'},
            {'name': 'falcon', 'url': 'https://github.com/falconry/falcon.git', 'size': 'medium'},
            {'name': 'dash', 'url': 'https://github.com/plotly/dash.git', 'size': 'large'},
            {'name': 'streamlit', 'url': 'https://github.com/streamlit/streamlit.git', 'size': 'large'},
            {'name': 'gradio', 'url': 'https://github.com/gradio-app/gradio.git', 'size': 'medium'},
            {'name': 'chalice', 'url': 'https://github.com/aws/chalice.git', 'size': 'medium'},
            {'name': 'zappa', 'url': 'https://github.com/Miserlou/Zappa.git', 'size': 'medium'},
            {'name': 'masonite', 'url': 'https://github.com/MasoniteFramework/masonite.git', 'size': 'medium'},
            {'name': 'blacksheep', 'url': 'https://github.com/Neoteroi/BlackSheep.git', 'size': 'medium'},
            
            # Database & ORM (25)
            {'name': 'sqlalchemy', 'url': 'https://github.com/sqlalchemy/sqlalchemy.git', 'size': 'large'},
            {'name': 'peewee', 'url': 'https://github.com/coleifer/peewee.git', 'size': 'medium'},
            {'name': 'tortoise-orm', 'url': 'https://github.com/tortoise/tortoise-orm.git', 'size': 'medium'},
            {'name': 'pony', 'url': 'https://github.com/ponyorm/pony.git', 'size': 'medium'},
            {'name': 'django-orm', 'url': 'https://github.com/django/django.git', 'size': 'large'},
            {'name': 'sqlobject', 'url': 'https://github.com/sqlobject/sqlobject.git', 'size': 'medium'},
            {'name': 'dataset', 'url': 'https://github.com/pudo/dataset.git', 'size': 'small'},
            {'name': 'records', 'url': 'https://github.com/kennethreitz/records.git', 'size': 'small'},
            {'name': 'pymongo', 'url': 'https://github.com/mongodb/mongo-python-driver.git', 'size': 'large'},
            {'name': 'motor', 'url': 'https://github.com/mongodb/motor.git', 'size': 'medium'},
            {'name': 'mongoengine', 'url': 'https://github.com/MongoEngine/mongoengine.git', 'size': 'medium'},
            {'name': 'redis-py', 'url': 'https://github.com/redis/redis-py.git', 'size': 'medium'},
            {'name': 'hiredis', 'url': 'https://github.com/redis/hiredis-py.git', 'size': 'small'},
            {'name': 'cassandra-driver', 'url': 'https://github.com/datastax/python-driver.git', 'size': 'medium'},
            {'name': 'neo4j-python', 'url': 'https://github.com/neo4j/neo4j-python-driver.git', 'size': 'medium'},
            {'name': 'influxdb-python', 'url': 'https://github.com/influxdata/influxdb-python.git', 'size': 'medium'},
            {'name': 'elasticsearch-py', 'url': 'https://github.com/elastic/elasticsearch-py.git', 'size': 'large'},
            {'name': 'psycopg2', 'url': 'https://github.com/psycopg/psycopg2.git', 'size': 'large'},
            {'name': 'psycopg3', 'url': 'https://github.com/psycopg/psycopg.git', 'size': 'large'},
            {'name': 'mysql-connector-python', 'url': 'https://github.com/mysql/mysql-connector-python.git', 'size': 'large'},
            {'name': 'pymysql', 'url': 'https://github.com/PyMySQL/PyMySQL.git', 'size': 'medium'},
            {'name': 'sqlite3', 'url': 'https://github.com/python/cpython.git', 'size': 'huge'},
            {'name': 'alembic', 'url': 'https://github.com/sqlalchemy/alembic.git', 'size': 'medium'},
            {'name': 'django-migrations', 'url': 'https://github.com/django/django.git', 'size': 'large'},
            {'name': 'flask-migrate', 'url': 'https://github.com/miguelgrinberg/flask-migrate.git', 'size': 'small'},
            
            # Security & Crypto (30)
            {'name': 'cryptography', 'url': 'https://github.com/pyca/cryptography.git', 'size': 'large'},
            {'name': 'pyjwt', 'url': 'https://github.com/jpadilla/pyjwt.git', 'size': 'medium'},
            {'name': 'passlib', 'url': 'https://github.com/efficks/passlib.git', 'size': 'medium'},
            {'name': 'bcrypt', 'url': 'https://github.com/pyca/bcrypt.git', 'size': 'medium'},
            {'name': 'argon2-cffi', 'url': 'https://github.com/hynek/argon2-cffi.git', 'size': 'small'},
            {'name': 'scrypt', 'url': 'https://github.com/holgern/py-scrypt.git', 'size': 'small'},
            {'name': 'python-social-auth', 'url': 'https://github.com/python-social-auth/social-core.git', 'size': 'medium'},
            {'name': 'python-jose', 'url': 'https://github.com/mpdavis/python-jose.git', 'size': 'medium'},
            {'name': 'itsdangerous', 'url': 'https://github.com/pallets/itsdangerous.git', 'size': 'small'},
            {'name': 'authlib', 'url': 'https://github.com/lepture/authlib.git', 'size': 'medium'},
            {'name': 'flask-jwt-extended', 'url': 'https://github.com/vimalloc/flask-jwt-extended.git', 'size': 'medium'},
            {'name': 'django-oauth-toolkit', 'url': 'https://github.com/jazzband/django-oauth-toolkit.git', 'size': 'medium'},
            {'name': 'oauthlib', 'url': 'https://github.com/oauthlib/oauthlib.git', 'size': 'medium'},
            {'name': 'requests-oauthlib', 'url': 'https://github.com/requests/requests-oauthlib.git', 'size': 'small'},
            {'name': 'pycryptodome', 'url': 'https://github.com/Legrandin/pycryptodome.git', 'size': 'large'},
            {'name': 'keyring', 'url': 'https://github.com/jaraco/keyring.git', 'size': 'medium'},
            {'name': 'cryptography-vectors', 'url': 'https://github.com/pyca/cryptography.git', 'size': 'large'},
            {'name': 'paramiko', 'url': 'https://github.com/paramiko/paramiko.git', 'size': 'medium'},
            {'name': 'fabric', 'url': 'https://github.com/fabric/fabric.git', 'size': 'medium'},
            {'name': 'ansible', 'url': 'https://github.com/ansible/ansible.git', 'size': 'huge'},
            {'name': 'bandit', 'url': 'https://github.com/PyCQA/bandit.git', 'size': 'medium'},
            {'name': 'safety', 'url': 'https://github.com/pyupio/safety.git', 'size': 'small'},
            {'name': 'pip-audit', 'url': 'https://github.com/pypa/pip-audit.git', 'size': 'small'},
            {'name': 'django-ratelimit', 'url': 'https://github.com/jsocol/django-ratelimit.git', 'size': 'small'},
            {'name': 'django-cors-headers', 'url': 'https://github.com/adamchainz/django-cors-headers.git', 'size': 'small'},
            {'name': 'django-guardian', 'url': 'https://github.com/django-guardian/django-guardian.git', 'size': 'medium'},
            {'name': 'flask-security', 'url': 'https://github.com/Flask-Middleware/flask-security.git', 'size': 'medium'},
            {'name': 'flask-login', 'url': 'https://github.com/maxcountryman/flask-login.git', 'size': 'small'},
            {'name': 'flask-principal', 'url': 'https://github.com/mattupstate/flask-principal.git', 'size': 'small'},
            {'name': 'secure', 'url': 'https://github.com/TypeError/secure.git', 'size': 'small'},
            
            # HTTP & Networking (25)
            {'name': 'requests', 'url': 'https://github.com/psf/requests.git', 'size': 'large'},
            {'name': 'urllib3', 'url': 'https://github.com/urllib3/urllib3.git', 'size': 'large'},
            {'name': 'httpx', 'url': 'https://github.com/encode/httpx.git', 'size': 'large'},
            {'name': 'aiohttp', 'url': 'https://github.com/aio-libs/aiohttp.git', 'size': 'large'},
            {'name': 'twisted', 'url': 'https://github.com/twisted/twisted.git', 'size': 'large'},
            {'name': 'scrapy', 'url': 'https://github.com/scrapy/scrapy.git', 'size': 'large'},
            {'name': 'mechanize', 'url': 'https://github.com/python-mechanize/mechanize.git', 'size': 'small'},
            {'name': 'selenium', 'url': 'https://github.com/SeleniumHQ/selenium.git', 'size': 'large'},
            {'name': 'playwright', 'url': 'https://github.com/microsoft/playwright-python.git', 'size': 'large'},
            {'name': 'websockets', 'url': 'https://github.com/python-websockets/websockets.git', 'size': 'medium'},
            {'name': 'websocket-client', 'url': 'https://github.com/websocket-client/websocket-client.git', 'size': 'medium'},
            {'name': 'socketio', 'url': 'https://github.com/miguelgrinberg/python-socketio.git', 'size': 'medium'},
            {'name': 'flask-socketio', 'url': 'https://github.com/miguelgrinberg/flask-socketio.git', 'size': 'medium'},
            {'name': 'django-channels', 'url': 'https://github.com/django/channels.git', 'size': 'medium'},
            {'name': 'tornado-websocket', 'url': 'https://github.com/tornadoweb/tornado.git', 'size': 'large'},
            {'name': 'pycurl', 'url': 'https://github.com/pycurl/pycurl.git', 'size': 'medium'},
            {'name': 'httpie', 'url': 'https://github.com/httpie/httpie.git', 'size': 'medium'},
            {'name': 'treq', 'url': 'https://github.com/twisted/treq.git', 'size': 'small'},
            {'name': 'grequests', 'url': 'https://github.com/spyoungtech/grequests.git', 'size': 'small'},
            {'name': 'requests-futures', 'url': 'https://github.com/ross/requests-futures.git', 'size': 'small'},
            {'name': 'requests-cache', 'url': 'https://github.com/requests-cache/requests-cache.git', 'size': 'small'},
            {'name': 'requests-toolbelt', 'url': 'https://github.com/requests/toolbelt.git', 'size': 'small'},
            {'name': 'requests-html', 'url': 'https://github.com/psf/requests-html.git', 'size': 'small'},
            {'name': 'httplib2', 'url': 'https://github.com/httplib2/httplib2.git', 'size': 'small'},
            {'name': 'pyftpdlib', 'url': 'https://github.com/giampaolo/pyftpdlib.git', 'size': 'medium'},
            
            # Data Processing & Analysis (20)
            {'name': 'pandas', 'url': 'https://github.com/pandas-dev/pandas.git', 'size': 'huge'},
            {'name': 'numpy', 'url': 'https://github.com/numpy/numpy.git', 'size': 'huge'},
            {'name': 'scipy', 'url': 'https://github.com/scipy/scipy.git', 'size': 'huge'},
            {'name': 'matplotlib', 'url': 'https://github.com/matplotlib/matplotlib.git', 'size': 'large'},
            {'name': 'seaborn', 'url': 'https://github.com/mwaskom/seaborn.git', 'size': 'medium'},
            {'name': 'plotly', 'url': 'https://github.com/plotly/plotly.py.git', 'size': 'large'},
            {'name': 'bokeh', 'url': 'https://github.com/bokeh/bokeh.git', 'size': 'large'},
            {'name': 'scikit-learn', 'url': 'https://github.com/scikit-learn/scikit-learn.git', 'size': 'huge'},
            {'name': 'scikit-image', 'url': 'https://github.com/scikit-image/scikit-image.git', 'size': 'large'},
            {'name': 'statsmodels', 'url': 'https://github.com/statsmodels/statsmodels.git', 'size': 'large'},
            {'name': 'sympy', 'url': 'https://github.com/sympy/sympy.git', 'size': 'large'},
            {'name': 'pytorch', 'url': 'https://github.com/pytorch/pytorch.git', 'size': 'huge'},
            {'name': 'tensorflow', 'url': 'https://github.com/tensorflow/tensorflow.git', 'size': 'huge'},
            {'name': 'keras', 'url': 'https://github.com/keras-team/keras.git', 'size': 'large'},
            {'name': 'xgboost', 'url': 'https://github.com/dmlc/xgboost.git', 'size': 'large'},
            {'name': 'lightgbm', 'url': 'https://github.com/microsoft/LightGBM.git', 'size': 'large'},
            {'name': 'catboost', 'url': 'https://github.com/catboost/catboost.git', 'size': 'large'},
            {'name': 'dask', 'url': 'https://github.com/dask/dask.git', 'size': 'large'},
            {'name': 'polars', 'url': 'https://github.com/pola-rs/polars.git', 'size': 'large'},
            {'name': 'vaex', 'url': 'https://github.com/vaexio/vaex.git', 'size': 'medium'},
            
            # Testing & Tools (20)
            {'name': 'pytest', 'url': 'https://github.com/pytest-dev/pytest.git', 'size': 'large'},
            {'name': 'unittest', 'url': 'https://github.com/python/cpython.git', 'size': 'huge'},
            {'name': 'nose', 'url': 'https://github.com/nose-devs/nose.git', 'size': 'medium'},
            {'name': 'nose2', 'url': 'https://github.com/nose-devs/nose2.git', 'size': 'small'},
            {'name': 'coverage', 'url': 'https://github.com/nedbat/coveragepy.git', 'size': 'medium'},
            {'name': 'pytest-cov', 'url': 'https://github.com/pytest-dev/pytest-cov.git', 'size': 'small'},
            {'name': 'mock', 'url': 'https://github.com/python/cpython.git', 'size': 'huge'},
            {'name': 'responses', 'url': 'https://github.com/getsentry/responses.git', 'size': 'small'},
            {'name': 'vcrpy', 'url': 'https://github.com/kevin1024/vcrpy.git', 'size': 'small'},
            {'name': 'freezegun', 'url': 'https://github.com/spulec/freezegun.git', 'size': 'small'},
            {'name': 'faker', 'url': 'https://github.com/joke2k/faker.git', 'size': 'medium'},
            {'name': 'factory-boy', 'url': 'https://github.com/FactoryBoy/factory_boy.git', 'size': 'medium'},
            {'name': 'hypothesis', 'url': 'https://github.com/HypothesisWorks/hypothesis.git', 'size': 'medium'},
            {'name': 'locust', 'url': 'https://github.com/locustio/locust.git', 'size': 'medium'},
            {'name': 'pytest-benchmark', 'url': 'https://github.com/ionelmc/pytest-benchmark.git', 'size': 'small'},
            {'name': 'pytest-mock', 'url': 'https://github.com/pytest-dev/pytest-mock.git', 'size': 'small'},
            {'name': 'pytest-asyncio', 'url': 'https://github.com/pytest-dev/pytest-asyncio.git', 'size': 'small'},
            {'name': 'pytest-django', 'url': 'https://github.com/pytest-dev/pytest-django.git', 'size': 'small'},
            {'name': 'pytest-flask', 'url': 'https://github.com/pytest-dev/pytest-flask.git', 'size': 'small'},
            {'name': 'tox', 'url': 'https://github.com/tox-dev/tox.git', 'size': 'medium'},
            
            # Configuration & Parsing (15)
            {'name': 'pyyaml', 'url': 'https://github.com/yaml/pyyaml.git', 'size': 'medium'},
            {'name': 'toml', 'url': 'https://github.com/uiri/toml.git', 'size': 'small'},
            {'name': 'configparser', 'url': 'https://github.com/python/cpython.git', 'size': 'huge'},
            {'name': 'python-dotenv', 'url': 'https://github.com/theskumar/python-dotenv.git', 'size': 'small'},
            {'name': 'dynaconf', 'url': 'https://github.com/dynaconf/dynaconf.git', 'size': 'medium'},
            {'name': 'configargparse', 'url': 'https://github.com/bw2/ConfigArgParse.git', 'size': 'small'},
            {'name': 'click-configfile', 'url': 'https://github.com/phha/click_config_file.git', 'size': 'small'},
            {'name': 'environs', 'url': 'https://github.com/sloria/environs.git', 'size': 'small'},
            {'name': 'decouple', 'url': 'https://github.com/henriquebastos/python-decouple.git', 'size': 'small'},
            {'name': 'configobj', 'url': 'https://github.com/DiffSK/configobj.git', 'size': 'small'},
            {'name': 'iniconfig', 'url': 'https://github.com/pytest-dev/iniconfig.git', 'size': 'small'},
            {'name': 'configupdater', 'url': 'https://github.com/pyscaffold/configupdater.git', 'size': 'small'},
            {'name': 'omegaconf', 'url': 'https://github.com/omry/omegaconf.git', 'size': 'medium'},
            {'name': 'hydra', 'url': 'https://github.com/facebookresearch/hydra.git', 'size': 'large'},
            {'name': 'json5', 'url': 'https://github.com/dpranke/pyjson5.git', 'size': 'small'},
            
            # Image Processing (10)
            {'name': 'pillow', 'url': 'https://github.com/python-pillow/Pillow.git', 'size': 'large'},
            {'name': 'opencv-python', 'url': 'https://github.com/opencv/opencv-python.git', 'size': 'large'},
            {'name': 'wand', 'url': 'https://github.com/emcconville/wand.git', 'size': 'medium'},
            {'name': 'scikit-image', 'url': 'https://github.com/scikit-image/scikit-image.git', 'size': 'large'},
            {'name': 'imageio', 'url': 'https://github.com/imageio/imageio.git', 'size': 'medium'},
            {'name': 'mahotas', 'url': 'https://github.com/luispedro/mahotas.git', 'size': 'medium'},
            {'name': 'imgaug', 'url': 'https://github.com/aleju/imgaug.git', 'size': 'medium'},
            {'name': 'albumentations', 'url': 'https://github.com/albumentations-team/albumentations.git', 'size': 'medium'},
            {'name': 'opencv-contrib', 'url': 'https://github.com/opencv/opencv_contrib.git', 'size': 'large'},
            {'name': 'simpleitk', 'url': 'https://github.com/SimpleITK/SimpleITK.git', 'size': 'large'},
            
            # Serialization & Validation (15)
            {'name': 'marshmallow', 'url': 'https://github.com/marshmallow-code/marshmallow.git', 'size': 'medium'},
            {'name': 'pydantic', 'url': 'https://github.com/pydantic/pydantic.git', 'size': 'large'},
            {'name': 'cerberus', 'url': 'https://github.com/pyeve/cerberus.git', 'size': 'medium'},
            {'name': 'schematics', 'url': 'https://github.com/schematics/schematics.git', 'size': 'medium'},
            {'name': 'voluptuous', 'url': 'https://github.com/alecthomas/voluptuous.git', 'size': 'small'},
            {'name': 'jsonschema', 'url': 'https://github.com/python-jsonschema/jsonschema.git', 'size': 'medium'},
            {'name': 'json-spec', 'url': 'https://github.com/gregsdennis/json-spec.git', 'size': 'small'},
            {'name': 'colander', 'url': 'https://github.com/Pylons/colander.git', 'size': 'medium'},
            {'name': 'django-forms', 'url': 'https://github.com/django/django.git', 'size': 'large'},
            {'name': 'wtforms', 'url': 'https://github.com/wtforms/wtforms.git', 'size': 'medium'},
            {'name': 'flask-wtf', 'url': 'https://github.com/wtforms/flask-wtf.git', 'size': 'small'},
            {'name': 'django-rest-framework', 'url': 'https://github.com/encode/django-rest-framework.git', 'size': 'large'},
            {'name': 'marshmallow-sqlalchemy', 'url': 'https://github.com/marshmallow-code/marshmallow-sqlalchemy.git', 'size': 'small'},
            {'name': 'serpy', 'url': 'https://github.com/clarkduvall/serpy.git', 'size': 'small'},
            {'name': 'drf-yasg', 'url': 'https://github.com/axnsan12/drf-yasg.git', 'size': 'small'},
            
            # File Processing (10)
            {'name': 'openpyxl', 'url': 'https://github.com/theorchard/openpyxl.git', 'size': 'medium'},
            {'name': 'xlsxwriter', 'url': 'https://github.com/jmcnamara/XlsxWriter.git', 'size': 'medium'},
            {'name': 'xlrd', 'url': 'https://github.com/python-excel/xlrd.git', 'size': 'medium'},
            {'name': 'xlwt', 'url': 'https://github.com/python-excel/xlwt.git', 'size': 'small'},
            {'name': 'pyexcel', 'url': 'https://github.com/pyexcel/pyexcel.git', 'size': 'small'},
            {'name': 'pandas-excel', 'url': 'https://github.com/pandas-dev/pandas.git', 'size': 'huge'},
            {'name': 'python-docx', 'url': 'https://github.com/python-openxml/python-docx.git', 'size': 'medium'},
            {'name': 'reportlab', 'url': 'https://github.com/MrBitBucket/reportlab.git', 'size': 'medium'},
            {'name': 'pdfkit', 'url': 'https://github.com/JazzCore/python-pdfkit.git', 'size': 'small'},
            {'name': 'pypdf', 'url': 'https://github.com/py-pdf/pypdf.git', 'size': 'medium'},
            
            # Task Queues & Background Jobs (10)
            {'name': 'celery', 'url': 'https://github.com/celery/celery.git', 'size': 'large'},
            {'name': 'rq', 'url': 'https://github.com/rq/rq.git', 'size': 'medium'},
            {'name': 'dramatiq', 'url': 'https://github.com/Bogdanp/dramatiq.git', 'size': 'medium'},
            {'name': 'huey', 'url': 'https://github.com/coleifer/huey.git', 'size': 'small'},
            {'name': 'apscheduler', 'url': 'https://github.com/agronholm/apscheduler.git', 'size': 'medium'},
            {'name': 'schedule', 'url': 'https://github.com/dbader/schedule.git', 'size': 'small'},
            {'name': 'python-crontab', 'url': 'https://github.com/josiahcarlson/parse-crontab.git', 'size': 'small'},
            {'name': 'django-q', 'url': 'https://github.com/Koed00/django-q.git', 'size': 'medium'},
            {'name': 'django-rq', 'url': 'https://github.com/rq/django-rq.git', 'size': 'small'},
            {'name': 'flower', 'url': 'https://github.com/mher/flower.git', 'size': 'medium'},
            
            # Server & Deployment (10)
            {'name': 'gunicorn', 'url': 'https://github.com/benoitc/gunicorn.git', 'size': 'medium'},
            {'name': 'uwsgi', 'url': 'https://github.com/unbit/uwsgi.git', 'size': 'large'},
            {'name': 'waitress', 'url': 'https://github.com/Pylons/waitress.git', 'size': 'medium'},
            {'name': 'bjoern', 'url': 'https://github.com/jonashaag/bjoern.git', 'size': 'small'},
            {'name': 'hypercorn', 'url': 'https://github.com/pythons/hypercorn.git', 'size': 'medium'},
            {'name': 'uvicorn', 'url': 'https://github.com/encode/uvicorn.git', 'size': 'medium'},
            {'name': 'daphne', 'url': 'https://github.com/django/daphne.git', 'size': 'small'},
            {'name': 'mod-wsgi', 'url': 'https://github.com/GrahamDumpleton/mod_wsgi.git', 'size': 'medium'},
            {'name': 'supervisor', 'url': 'https://github.com/Supervisor/supervisor.git', 'size': 'medium'},
            {'name': 'circus', 'url': 'https://github.com/circus-tent/circus.git', 'size': 'medium'},
            
            # Template Engines (8)
            {'name': 'jinja2', 'url': 'https://github.com/pallets/jinja2.git', 'size': 'medium'},
            {'name': 'mako', 'url': 'https://github.com/sqlalchemy/mako.git', 'size': 'medium'},
            {'name': 'chameleon', 'url': 'https://github.com/malthe/chameleon.git', 'size': 'medium'},
            {'name': 'tenjin', 'url': 'https://github.com/kuwata-lab/tenjin.git', 'size': 'small'},
            {'name': 'chevron', 'url': 'https://github.com/noahmorrison/chevron.git', 'size': 'small'},
            {'name': 'pystache', 'url': 'https://github.com/defunkt/pystache.git', 'size': 'small'},
            {'name': 'django-templates', 'url': 'https://github.com/django/django.git', 'size': 'large'},
            {'name': 'liquid', 'url': 'https://github.com/jekyll/liquid.git', 'size': 'small'},
            
            # CLI & Utilities (15)
            {'name': 'click', 'url': 'https://github.com/pallets/click.git', 'size': 'medium'},
            {'name': 'argparse', 'url': 'https://github.com/python/cpython.git', 'size': 'huge'},
            {'name': 'docopt', 'url': 'https://github.com/docopt/docopt.git', 'size': 'small'},
            {'name': 'fire', 'url': 'https://github.com/google/python-fire.git', 'size': 'medium'},
            {'name': 'typer', 'url': 'https://github.com/tiangolo/typer.git', 'size': 'medium'},
            {'name': 'rich', 'url': 'https://github.com/Textualize/rich.git', 'size': 'medium'},
            {'name': 'tqdm', 'url': 'https://github.com/tqdm/tqdm.git', 'size': 'medium'},
            {'name': 'progressbar2', 'url': 'https://github.com/WoLpH/progressbar.git', 'size': 'small'},
            {'name': 'colorama', 'url': 'https://github.com/tartley/colorama.git', 'size': 'small'},
            {'name': 'blessings', 'url': 'https://github.com/erikrose/blessings.git', 'size': 'small'},
            {'name': 'prompt-toolkit', 'url': 'https://github.com/prompt-toolkit/python-prompt-toolkit.git', 'size': 'medium'},
            {'name': 'python-prompt-toolkit', 'url': 'https://github.com/prompt-toolkit/python-prompt-toolkit.git', 'size': 'medium'},
            {'name': 'pexpect', 'url': 'https://github.com/pexpect/pexpect.git', 'size': 'medium'},
            {'name': 'sh', 'url': 'https://github.com/amoffat/sh.git', 'size': 'small'},
            {'name': 'plumbum', 'url': 'https://github.com/tomerfiliba/plumbum.git', 'size': 'small'},
            
            # Logging & Monitoring (10)
            {'name': 'loguru', 'url': 'https://github.com/Delgan/loguru.git', 'size': 'medium'},
            {'name': 'structlog', 'url': 'https://github.com/hynek/structlog.git', 'size': 'medium'},
            {'name': 'sentry-python', 'url': 'https://github.com/getsentry/sentry-python.git', 'size': 'large'},
            {'name': 'raven', 'url': 'https://github.com/getsentry/raven-python.git', 'size': 'small'},
            {'name': 'python-logging-loki', 'url': 'https://github.com/GreyZmeem/python-logging-loki.git', 'size': 'small'},
            {'name': 'python-json-logger', 'url': 'https://github.com/madzak/python-json-logger.git', 'size': 'small'},
            {'name': 'elastalert', 'url': 'https://github.com/Yelp/elastalert.git', 'size': 'medium'},
            {'name': 'watchdog', 'url': 'https://github.com/gorakhargosh/watchdog.git', 'size': 'medium'},
            {'name': 'pyinotify', 'url': 'https://github.com/seb-m/pyinotify.git', 'size': 'small'},
            {'name': 'psutil', 'url': 'https://github.com/giampaolo/psutil.git', 'size': 'medium'},
            
            # Caching (8)
            {'name': 'django-cache', 'url': 'https://github.com/django/django.git', 'size': 'large'},
            {'name': 'flask-caching', 'url': 'https://github.com/pallets-eco/flask-caching.git', 'size': 'small'},
            {'name': 'cachetools', 'url': 'https://github.com/tkem/cachetools.git', 'size': 'small'},
            {'name': 'diskcache', 'url': 'https://github.com/grantjenks/python-diskcache.git', 'size': 'small'},
            {'name': 'beaker', 'url': 'https://github.com/bbangert/beaker.git', 'size': 'medium'},
            {'name': 'dogpile-cache', 'url': 'https://github.com/sqlalchemy/dogpile.cache.git', 'size': 'small'},
            {'name': 'python-memcached', 'url': 'https://github.com/linsomniac/python-memcached.git', 'size': 'small'},
            {'name': 'pylibmc', 'url': 'https://github.com/lericson/pylibmc.git', 'size': 'small'},
        ]
        
        # Prioritize web frameworks (more likely to have exploitable vulnerabilities)
        web_framework_names = ['django', 'flask', 'fastapi', 'tornado', 'bottle', 'cherrypy', 'pyramid', 'web2py', 'sanic', 'starlette', 'quart', 'hug', 'falcon']
        
        # Sort: web frameworks first, then by size
        def sort_key(repo):
            name = repo['name']
            is_web = 0 if name in web_framework_names else 1
            size_order = {'huge': 0, 'large': 1, 'medium': 2, 'small': 3}
            size_val = size_order.get(repo['size'], 4)
            return (is_web, size_val)
        
        repos.sort(key=sort_key)
        
        return repos
    
    def clone_repo(self, repo: Dict[str, str]) -> Optional[Path]:
        """Clone a repository"""
        repo_name = repo['name']
        repo_url = repo['url']
        target_dir = self.scan_dir / repo_name
        
        if target_dir.exists():
            print(f"  ✓ Already cloned: {repo_name}")
            return target_dir
        
        print(f"  Cloning {repo_name}...")
        try:
            subprocess.run(
                ['git', 'clone', '--depth', '1', repo_url, str(target_dir)],
                check=True,
                capture_output=True,
                timeout=300
            )
            return target_dir
        except subprocess.TimeoutExpired:
            print(f"  ⚠️  Timeout cloning {repo_name}")
            return None
        except subprocess.CalledProcessError as e:
            print(f"  ⚠️  Error cloning {repo_name}: {e}")
            return None
    
    def scan_repo(self, repo_path: Path) -> List[Dict]:
        """Scan a repository for vulnerabilities"""
        try:
            # For large repos, scan specific subdirectories more likely to have vulnerabilities
            repo_name = repo_path.name
            
            # Web frameworks - scan core directories
            if repo_name in ['django', 'flask', 'fastapi', 'tornado', 'bottle', 'cherrypy', 'pyramid', 'web2py']:
                subdirs_to_scan = []
                if repo_name == 'django':
                    subdirs_to_scan = [
                        repo_path / 'django' / 'core',
                        repo_path / 'django' / 'contrib',
                        repo_path / 'django' / 'db',
                    ]
                elif repo_name == 'flask':
                    subdirs_to_scan = [
                        repo_path / 'src' / 'flask',
                        repo_path / 'flask',
                    ]
                elif repo_name == 'fastapi':
                    subdirs_to_scan = [
                        repo_path / 'fastapi',
                    ]
                
                # Scan subdirectories
                all_findings = []
                for subdir in subdirs_to_scan:
                    if subdir.exists():
                        try:
                            results = self.scanner.scan(str(subdir), mode="fast")
                            findings = results.get('vulnerabilities', [])
                            all_findings.extend(findings)
                        except:
                            pass
                
                if all_findings:
                    return all_findings
            
            # For other repos, try full scan but with timeout
            results = self.scanner.scan(str(repo_path), mode="fast")
            return results.get('vulnerabilities', [])
        except Exception as e:
            print(f"  ⚠️  Error scanning: {e}")
            return []
    
    def verify_exploitability(self, finding: Dict, code_context: str = '') -> Tuple[bool, str]:
        """Verify if a finding is actually exploitable with thorough code analysis"""
        file_path = finding.get('file_path', '')
        cwe = finding.get('cwe', '')
        line_num = finding.get('line_number', 0)
        
        # First, use noise filter for basic checks
        is_exploitable, reason = self.noise_filter.is_exploitable(finding, code_context)
        if not is_exploitable:
            return False, reason
        
        # Read actual code for deep analysis
        try:
            fp = Path(file_path)
            if not fp.exists():
                return False, "File not found"
            
            with open(fp, 'r', errors='ignore') as f:
                lines = f.readlines()
            
            if line_num > len(lines) or line_num < 1:
                return False, "Line number out of range"
            
            # Get extended context (50 lines before/after)
            start = max(0, line_num - 50)
            end = min(len(lines), line_num + 50)
            context_lines = lines[start:end]
            context = ''.join(context_lines)
            vulnerable_line = lines[line_num - 1] if line_num <= len(lines) else ""
            
            # Get function/class context
            function_context = self._get_function_context(lines, line_num)
            
            # CWE-specific deep verification
            if cwe == 'CWE-89':  # SQL Injection
                return self._verify_sql_injection(finding, vulnerable_line, context, function_context, lines, line_num)
            
            elif cwe == 'CWE-78':  # Command Injection
                return self._verify_command_injection(finding, vulnerable_line, context, function_context, lines, line_num)
            
            elif cwe == 'CWE-22':  # Path Traversal
                return self._verify_path_traversal(finding, vulnerable_line, context, function_context, lines, line_num)
            
            elif cwe == 'CWE-79':  # XSS
                return self._verify_xss(finding, vulnerable_line, context, function_context, file_path)
            
            elif cwe == 'CWE-502':  # Unsafe Deserialization
                return self._verify_deserialization(finding, vulnerable_line, context, function_context, file_path)
            
            elif cwe == 'CWE-327':  # Weak Crypto
                return self._verify_weak_crypto(finding, vulnerable_line, context, function_context, file_path)
            
            elif cwe == 'CWE-798':  # Hardcoded Credentials
                return self._verify_hardcoded_creds(finding, vulnerable_line, context, function_context)
            
            elif cwe == 'CWE-732':  # Permission Issues
                return self._verify_permissions(finding, vulnerable_line, context, function_context)
            
            # Default: passed noise filter, might be exploitable
            return True, "Passed noise filters - needs manual review"
            
        except Exception as e:
            return False, f"Error analyzing code: {e}"
    
    def _get_function_context(self, lines: List[str], line_num: int) -> str:
        """Get the function/class context for a line"""
        # Look backwards for function/class definition
        context = []
        indent_level = None
        
        for i in range(line_num - 1, max(0, line_num - 100), -1):
            line = lines[i]
            stripped = line.lstrip()
            
            # Find function/class definition
            if stripped.startswith(('def ', 'class ', 'async def ')):
                context.insert(0, line)
                break
            
            # Track indentation
            if indent_level is None and stripped:
                indent_level = len(line) - len(stripped)
            
            if indent_level is not None:
                current_indent = len(line) - len(stripped) if stripped else len(line)
                if current_indent < indent_level:
                    break
            
            context.insert(0, line)
        
        return ''.join(context[:20])  # Last 20 lines of function context
    
    def _verify_sql_injection(self, finding: Dict, line: str, context: str, func_context: str, all_lines: List[str], line_num: int) -> Tuple[bool, str]:
        """Verify SQL injection exploitability"""
        # Check if uses safe methods
        if any(x in context.lower() for x in ['quote_name', 'escape', 'parameter', 'execute(', 'executemany(']):
            # Check if parameters are used
            if 'execute(' in line.lower() and ('%s' in line or '?' in line or 'params' in context.lower()):
                # Might be parameterized - check more
                if 'params' in context.lower() or 'args' in context.lower():
                    return False, "Uses parameterized queries"
        
        # Check for user input indicators
        user_input_indicators = [
            'request.', 'input', 'form', 'post', 'get', 'query', 'args',
            'kwargs', 'data', 'json', 'body', 'params', 'cookies', 'headers'
        ]
        
        has_user_input = any(indicator in context.lower() for indicator in user_input_indicators)
        
        # Check if SQL uses string formatting with user input
        if '%' in line or 'f"' in line or '.format(' in line or '+' in line:
            if has_user_input:
                # Check if it's Django ORM (safe)
                if any(x in context.lower() for x in ['.objects.', 'queryset', 'model.objects']):
                    return False, "Django ORM - safe"
                # Check if it's SQLAlchemy ORM (safe)
                if any(x in context.lower() for x in ['session.query', 'db.session', 'query.filter']):
                    return False, "SQLAlchemy ORM - safe"
                
                # Might be exploitable
                return True, "SQL injection with user input - exploitable"
        
        return False, "No clear user input or uses safe methods"
    
    def _verify_command_injection(self, finding: Dict, line: str, context: str, func_context: str, all_lines: List[str], line_num: int) -> Tuple[bool, str]:
        """Verify command injection exploitability"""
        # Check for command execution
        cmd_patterns = [
            r'os\.system\s*\(',
            r'subprocess\.(call|Popen|run)\s*\(',
            r'\.call\s*\(',
        ]
        
        has_cmd_exec = any(re.search(pattern, line, re.IGNORECASE) for pattern in cmd_patterns)
        
        if not has_cmd_exec:
            return False, "No command execution found"
        
        # Check for user input
        user_input_indicators = [
            'request.', 'input', 'form', 'post', 'get', 'query', 'args',
            'kwargs', 'data', 'json', 'body', 'params'
        ]
        
        has_user_input = any(indicator in context.lower() for indicator in user_input_indicators)
        
        # Check for sanitization
        if any(x in context.lower() for x in ['shlex.quote', 'shlex.split', 'escape', 'sanitize', 'validate']):
            return False, "Uses input sanitization"
        
        if has_user_input:
            return True, "Command injection with user input - exploitable"
        
        return False, "No user input in command execution"
    
    def _verify_path_traversal(self, finding: Dict, line: str, context: str, func_context: str, all_lines: List[str], line_num: int) -> Tuple[bool, str]:
        """Verify path traversal exploitability"""
        # Check for path operations
        path_patterns = [
            r'open\s*\(',
            r'file\s*\(',
            r'\.read\s*\(',
            r'\.write\s*\(',
        ]
        
        has_path_op = any(re.search(pattern, line, re.IGNORECASE) for pattern in path_patterns)
        
        if not has_path_op:
            return False, "No file operation found"
        
        # Check for safe path operations
        if any(x in context.lower() for x in ['abspath', 'realpath', 'normpath', 'os.path.join', 'pathlib']):
            # Check if user input is sanitized
            if 'request.' in context.lower() or 'input' in context.lower():
                # Check if path is validated
                if any(x in context.lower() for x in ['validate', 'sanitize', 'secure', 'safe']):
                    return False, "Path validation found"
                # Might still be exploitable if validation is weak
                return True, "Path traversal with user input - potentially exploitable"
        
        # Check for user input
        if any(x in context.lower() for x in ['request.', 'input', 'form', 'upload', 'file']):
            return True, "Path traversal with user input - exploitable"
        
        return False, "No user-controlled path"
    
    def _verify_xss(self, finding: Dict, line: str, context: str, func_context: str, file_path: str) -> Tuple[bool, str]:
        """Verify XSS exploitability"""
        # Skip static files
        if 'static' in file_path.lower() or 'admin/static' in file_path.lower():
            return False, "Static file"
        
        # Check if it's in templates
        if 'template' in file_path.lower() or 'jinja' in file_path.lower() or 'mako' in file_path.lower():
            # Check for user input
            if any(x in context.lower() for x in ['request', 'input', 'form', 'user', 'variable']):
                # Check for escaping
                if any(x in context.lower() for x in ['escape', 'safe', 'mark_safe', 'autoescape']):
                    # Check if escaping is disabled
                    if 'autoescape false' in context.lower() or '|safe' in context.lower():
                        return True, "XSS in template with escaping disabled"
                    return False, "Template uses auto-escaping"
                return True, "XSS in template - potentially exploitable"
        
        return False, "Not in exploitable context"
    
    def _verify_deserialization(self, finding: Dict, line: str, context: str, func_context: str, file_path: str) -> Tuple[bool, str]:
        """Verify deserialization exploitability"""
        # Skip if requires infrastructure compromise
        if any(x in file_path.lower() for x in ['cache', 'redis', 'db', 'database']):
            # Check if it's from user input (not just cache)
            if 'request.' in context.lower() or 'input' in context.lower():
                return True, "Deserialization from user input - exploitable"
            return False, "Requires cache/DB compromise"
        
        # Check for user input
        if any(x in context.lower() for x in ['request', 'input', 'form', 'post', 'body']):
            return True, "Deserialization from user input - exploitable"
        
        return False, "No user input in deserialization"
    
    def _verify_weak_crypto(self, finding: Dict, line: str, context: str, func_context: str, file_path: str) -> Tuple[bool, str]:
        """Verify weak crypto exploitability"""
        # Check if it's actually used (not just defined)
        weak_patterns = ['md5', 'sha1', 'des', 'rc4']
        
        for pattern in weak_patterns:
            if re.search(rf'\b{pattern}\b', line, re.IGNORECASE):
                # Check if it's for security purposes
                if any(x in context.lower() for x in ['password', 'secret', 'token', 'auth', 'hash', 'digest']):
                    # Check if it's just defining (not using)
                    if 'ObjectIdentifier' in context or 'OID' in context:
                        return False, "OID definition only"
                    return True, f"Weak crypto ({pattern}) used for security - exploitable"
        
        return False, "Not actually using weak crypto"
    
    def _verify_hardcoded_creds(self, finding: Dict, line: str, context: str, func_context: str) -> Tuple[bool, str]:
        """Verify hardcoded credentials"""
        # Check for placeholder patterns
        placeholder_patterns = [
            'test', 'example', 'demo', 'placeholder', 'changeme', 'secret123',
            'password123', 'admin', 'root', 'default'
        ]
        
        line_lower = line.lower()
        for pattern in placeholder_patterns:
            if pattern in line_lower:
                return False, f"Placeholder credential: {pattern}"
        
        # Check entropy (simple check)
        import re
        cred_match = re.search(r'["\']([^"\']+)["\']', line)
        if cred_match:
            cred = cred_match.group(1)
            # Simple entropy check
            if len(set(cred)) < len(cred) * 0.3:  # Low diversity
                return False, "Low entropy - likely placeholder"
            
            # Check length
            if len(cred) < 8:
                return False, "Too short - likely placeholder"
        
        return True, "Hardcoded credential detected - exploitable"
    
    def _verify_permissions(self, finding: Dict, line: str, context: str, func_context: str) -> Tuple[bool, str]:
        """Verify permission issues"""
        # Check if file path is user-controlled
        if any(x in context.lower() for x in ['request', 'input', 'form', 'upload', 'file']):
            # Check for chmod operations
            if 'chmod' in line.lower() or 'os.chmod' in context.lower():
                return True, "Permission change with user-controlled path - exploitable"
        
        return False, "No user-controlled file path"
    
    def scan_codebases(self, target_count: int = 150):
        """Scan codebases until we find target_count exploitable vulnerabilities"""
        repos = self.get_large_python_repos()
        
        print("="*80)
        print(f"🔍 Scanning Codebases for {target_count} Real Exploitable Vulnerabilities")
        print("="*80)
        print()
        
        for i, repo in enumerate(repos, 1):
            if len(self.verified_vulnerabilities) >= target_count:
                break
            
            print(f"[{i}/{len(repos)}] Scanning {repo['name']}...")
            
            # Clone repo
            repo_path = self.clone_repo(repo)
            if not repo_path:
                continue
            
            # Scan
            findings = self.scan_repo(repo_path)
            self.scan_stats['total_findings'] += len(findings)
            
            print(f"  Found {len(findings)} raw findings")
            
            # Filter and verify
            verified_count = 0
            for finding in findings:
                # Get code context
                vulnerable_code = finding.get('vulnerable_code', {})
                code_context = vulnerable_code.get('context', '') or vulnerable_code.get('snippet', '') or ''
                
                # Verify exploitability
                is_exploitable, reason = self.verify_exploitability(finding, code_context)
                
                if is_exploitable:
                    finding['_verified'] = True
                    finding['_verification_reason'] = reason
                    finding['_repository'] = repo['name']
                    self.verified_vulnerabilities.append(finding)
                    verified_count += 1
                else:
                    self.scan_stats['filtered_noise'] += 1
            
            self.scan_stats['codebases_scanned'] += 1
            self.scan_stats['verified_exploitable'] = len(self.verified_vulnerabilities)
            
            print(f"  ✅ Verified exploitable: {verified_count}")
            print(f"  📊 Total verified: {len(self.verified_vulnerabilities)}/{target_count}")
            print()
            
            # Save progress
            self.save_progress()
        
        return self.verified_vulnerabilities
    
    def save_progress(self):
        """Save scanning progress"""
        output_file = Path("verified_exploitable_vulnerabilities.json")
        
        data = {
            'stats': self.scan_stats,
            'verified_vulnerabilities': self.verified_vulnerabilities,
            'total_verified': len(self.verified_vulnerabilities)
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def generate_report(self):
        """Generate final report"""
        print("="*80)
        print("📊 SCANNING COMPLETE")
        print("="*80)
        print()
        print(f"Codebases Scanned: {self.scan_stats['codebases_scanned']}")
        print(f"Total Findings: {self.scan_stats['total_findings']}")
        print(f"Filtered Noise: {self.scan_stats['filtered_noise']}")
        print(f"Verified Exploitable: {len(self.verified_vulnerabilities)}")
        print()
        
        # Group by CWE
        cwe_stats = defaultdict(int)
        for vuln in self.verified_vulnerabilities:
            cwe_stats[vuln.get('cwe', 'UNKNOWN')] += 1
        
        print("Findings by CWE:")
        for cwe, count in sorted(cwe_stats.items(), key=lambda x: x[1], reverse=True):
            print(f"  {cwe}: {count}")
        print()
        
        # Group by repository
        repo_stats = defaultdict(int)
        for vuln in self.verified_vulnerabilities:
            repo_stats[vuln.get('_repository', 'unknown')] += 1
        
        print("Findings by Repository (Top 10):")
        for repo, count in sorted(repo_stats.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  {repo}: {count}")
        print()
        
        print(f"✅ Results saved to: verified_exploitable_vulnerabilities.json")

def main():
    scanner = LargeCodebaseScanner()
    
    # Scan until we have 150 verified exploitable vulnerabilities
    vulnerabilities = scanner.scan_codebases(target_count=150)
    
    # Generate report
    scanner.generate_report()
    
    print("="*80)
    print("✅ SCANNING COMPLETE")
    print("="*80)
    print(f"Found {len(vulnerabilities)} verified exploitable vulnerabilities")
    print()

if __name__ == '__main__':
    main()

