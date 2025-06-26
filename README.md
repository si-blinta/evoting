# CommRevote

## Installation

```bash
git clone https://github.com/si-blinta/evoting.git
cd evoting/
python3 -m venv venv/
. venv/bin/activate
pip install -r requirements.txt
```
## Running
### Running the server

```bash
python3 -m server.main
```
### Running the simulation
```bash
#eligibility phase:
test/eligibility.sh
#commit phase:
test/commit.sh
#reveal phase
test/reveal.sh
```
### Commands
```bash
#initialize wallet:
python3 -m client.tools.votemanager <wallet> init --passphrase <passphrase>
#Send eligibility request to the server
python3 -m client.main <wallet> eligibility --id <id>
#Load a commit into a wallet:
python3 -m client.tools.votemanager <wallet> commit --candidate <candidate> --passphrase <passphrase>
#send commit request to the server
python3 -m client.main <wallet> commit
#send reveal to the server
python3 -m client.main <> reveal
```
## Config
Candidates,Voters ID ... are in server/data.py

For debug, modify logger level INFO -> DEBUG to see the packets