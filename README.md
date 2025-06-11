git clone …
cd iot-blockchain-poc
source venv/bin/activate
npm install -g ganache
pip install -r requirements.txt
./scripts/compile_contract.py
./scripts/deploy_contract.py
python flask_server/app.py
