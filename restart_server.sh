kill $(lsof -t -i:5001)
./venv/bin/python server.py &
# lsof -t -i:5001 | xargs kill -9