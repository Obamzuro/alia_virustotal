#! /bin/bash
python3 -m venv checkpoint_test
cd ./checkpoint_test
source ./bin/activate
pip install -r ../requirements.txt
echo "Type your API ID: "
read API_ID
sed -i "s/####################/$API_ID/g" ../main.py
